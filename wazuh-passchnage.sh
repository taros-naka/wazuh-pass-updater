#!/bin/bash

# Wazuh-docker用 パスワード変更スクリプト
# 対応バージョン: Wazuh 4.12.0 (Docker Compose構成)
# Ubuntu Server 24.04 など向け
# 実行例: bash ./wazuh-password-change.sh -a
#※　正常なcomposeファイルが必要です。
#※　このスクリプトはsudo権限で実行する必要があります
#※　Wazuh Stackの再起動と設定の反映を行います
#※　Wazuh StackのWeb UIが応答するまで待機します
#※　セキュリティ設定の反映を行います
#※　パスワードの設定は特殊記号は極力使用しないでください


set -euo pipefail

# sudo権限で実行
if [[ $EUID -ne 0 ]]; then
    echo "このスクリプトはsudo権限で実行する必要があります。"
    exit 1
fi


# ###################################################################################
# 環境変数の設定
# ###################################################################################

URL="https://localhost:443"

################################################################
# 　動的な連想配列を使用してアカウント情報を管理
# アカウントの連想配列
# types: アカウントタイプの配列
# ACCOUNT_VARS: アカウント情報を格納する連想配列
# 例: types=("indexer" "manager" "kibana")
#      ACCOUNT_VARS["indexer,account"]="admin"
#      ACCOUNT_VARS["indexer,user_env"]="INDEXER_USERNAME"
#      ACCOUNT_VARS["indexer,pass_env"]="INDEXER_PASSWORD"
#      ACCOUNT_VARS["indexer,pass"]="new_password"
#      ACCOUNT_VARS["indexer,hashed"]="hashed_password"
# 　このスクリプトでは、アカウントの種類ごとに
# 
################################################################

# 　動的な連想配列を使用してアカウント情報を管理
# アカウントの連想配列
declare -A ACCOUNT_VARS
types=()

# 関数：新しいアカウントタイプを追加する
add_account_type() {
  local type="$1"
  local account_name="$2"
  local user_env="$3"
  local pass_env="$4"

  types+=("$type")
  ACCOUNT_VARS["$type,account"]="$account_name"
  ACCOUNT_VARS["$type,user_env"]="$user_env"
  ACCOUNT_VARS["$type,pass_env"]="$pass_env"
}

add_pass_type() {
  local type="$1"
  local PASSWORD="$2"
  local HASHED_PASS="$3"

  ACCOUNT_VARS["$type,pass"]="$PASSWORD"
  ACCOUNT_VARS["$type,hashed"]="$HASHED_PASS"
}

# 初期アカウントタイプの追加
# 動的に追加
# 例: 相称 アカウント名　ユーザー環境変数 パスワード環境変数
add_account_type "indexer" "admin" "INDEXER_USERNAME" "INDEXER_PASSWORD"
add_account_type "manager" "wazuh-wui" "MANAGER_USERNAME" "MANAGER_PASSWORD"
add_account_type "kibana" "kibanaserver" "KIBANA_USERNAME" "KIBANA_PASSWORD"

# # 使うときはループで回す
# for type in "${types[@]}"; do
#   echo "Type: $type"
#   echo "  Account Name: ${ACCOUNT_VARS["$type,account"]}"
#   echo "  User Env: ${ACCOUNT_VARS["$type,user_env"]}"
#   echo "  Pass Env: ${ACCOUNT_VARS["$type,pass_env"]}"
# done



# 必要コマンド確認
command -v docker > /dev/null || { echo "Docker がインストールされていません"; exit 1; }
command -v docker compose > /dev/null || { echo "Docker Compose v2 が必要です (例: docker compose up)"; exit 1; }



#　　新しいパスワードを取得する関数
#    引数1: アカウント名
#    戻り値: 新しいパスワード
#    パスワード変更がキャンセルされた場合は空文字列を返す
new_password_make() {
    
    local ACCOUNT_NAME="$1"
    local NEW_PASSWORD=""
    local CONFIRM_PASSWORD=""

    read -s -p "新しい ${ACCOUNT_NAME} パスワードを入力してください: " NEW_PASSWORD >&2
    echo >&2
    if [[ -z "$NEW_PASSWORD" ]]; then
        echo "❌ パスワードは空のため、${ACCOUNT_NAME} のパスワード変更をスキップします。" >&2
        echo "" >&1
        return 1
    fi

    read -s -p "もう一度入力してください: " CONFIRM_PASSWORD >&2
    echo >&2
    if [[ "$NEW_PASSWORD" != "$CONFIRM_PASSWORD" ]]; then
        echo "❌ パスワードが一致しません。再実行してください。" >&2
        echo "" >&1
        return 1
    fi

    echo "$NEW_PASSWORD" >&1
    return 0
}


#  hash取得関数
get_password_hash() {
    # $1 は新しいパスワード
    if [[ -z "$1" ]]; then
        echo "❌ パスワードが指定されていません" >&2
        exit 1
    fi
    local PASSWORD="$1"
    echo "🔐 パスワードハッシュを生成中..." >&2
    local HASHED_PASSWORD=$(docker run --rm wazuh/wazuh-indexer:4.12.0 \
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh \
    -p "$PASSWORD")
    if [[ -z "$HASHED_PASSWORD" ]]; then
        echo "❌ パスワードハッシュの生成に失敗しました。" >&2
        exit 1
    fi
    echo "✅ ハッシュ化されたパスワード: $HASHED_PASSWORD" >&2
    echo "$HASHED_PASSWORD"  >&1
    return 0
}


#  internal_users.yml のハッシュ値変更
#  引数1: ユーザー名
#  引数2: ハッシュ化されたパスワード
#  戻り値: 成功時は0、失敗時は1
#  使用例: internal_users_update "wazuh-indexer" "hashed_password"
internal_users_update() {
    local USERNAME="$1"
    local HASHED_PASSWORD="$2"
    INTERNAL_USERS_FILE="./config/wazuh_indexer/internal_users.yml"

    if [[ -z "$USERNAME" || -z "$HASHED_PASSWORD" ]]; then
        echo "❌ 使い方: $0 <username> <hashed_password>" >&2
        exit 1
    fi
    # ハッシュの特殊文字を安全にエスケープ
    ESCAPED_HASH=$(printf '%s\n' "$HASHED_PASSWORD" | sed 's/[\/&]/\\&/g')

    # 対象ユーザーのhash行だけを置き換える
    sed -i "/^$USERNAME:/,/^[^ ]/ s|^\(\s*hash:\s*\).*|\1\"$ESCAPED_HASH\"|" "$INTERNAL_USERS_FILE"

    echo "✅ ユーザー '$USERNAME' の hash パスワードを更新しました。" >&2
    return 0
}   


# .env ファイルのパスワード更新
# 引数1: 環境変数名 (例: "INDEXER_USERNAME")
# 引数2: 新しいパスワード
# 戻り値: 成功時は0、失敗時は1
# 使用例: env_password_update "INDEXER_USERNAME" "new_password_make"
env_password_update() {
    local CONST="$1"
    local NEW_PASSWORD="$2"
    local ENV_FILE="./.env"
    if [[ -f "$ENV_FILE" ]]; then
        echo "🔧 .env ファイルのパスワードを更新中..."
        sed -i "s|^\(${CONST}=\).*|\1$NEW_PASSWORD|" "$ENV_FILE"
        
        echo "✅ $CONSTのパスワードが更新されました。"
    else
        echo "⚠️ .env ファイルが見つかりません。手動で修正してください。"
        exit 1
    fi
    return 0
}

update(){
    # 引数1: アカウントタイプ (例: "indexer")
    # 例：indexer, manager, kibana
    local TYPE="$1"

    # アカウント名：admin, wazuh-wui, kibanaserver 
    local ACCOUNT_NAME="${ACCOUNT_VARS["$TYPE,account"]}"
    # ユーザー環境変数: INDEXER_USERNAME, MANAGER_USERNAME, KIBANA_USERNAME
    local USER_ENV="${ACCOUNT_VARS["$TYPE,user_env"]}"
    # パスワード環境変数: INDEXER_PASSWORD, MANAGER_PASSWORD, KIBANA_PASSWORD
    local PASS_ENV="${ACCOUNT_VARS["$TYPE,pass_env"]}"
    # パスワード
    local ACCOUNT_PASSWORD="${ACCOUNT_VARS["$TYPE,pass"]}"
    # ハッシュ化されたパスワード
    local HASHED_PASSWORD="${ACCOUNT_VARS["$TYPE,hashed"]}"

    # internal_users.yml の更新
    if ! internal_users_update "$ACCOUNT_NAME" "$HASHED_PASSWORD"; then
        echo "❌ internal_users.yml の更新に失敗しました。" >&2
        exit 1
    fi
    echo "✅ internal_users.yml の更新が完了しました。"
    # .env ファイルの更新
    if ! env_password_update "$PASS_ENV" "$ACCOUNT_PASSWORD"; then
        echo "❌ .env ファイルの更新に失敗しました。" >&2
        exit 1
    fi
    echo "✅ .env ファイルの更新が完了しました。"
    return 0

}


docker_start() {
    # Wazuh を再起動
    echo "🔄 Wazuh Stack を再起動します..."
    docker compose down
    docker compose up -d
    local HOST_URL="$1"



    # Wazuh Dashboardが応答するまで待機
    local MAX_RETRIES=60
    local INTERVAL=15
    echo "⏳ Wazuh Dashboard のWeb画面が応答するのを待機中..."

    for i in $(seq 1 $MAX_RETRIES); do
        STATUS_CODE=$(curl -k -L -I "$HOST_URL/app/login" \
        -o /dev/null -s -w "%{http_code}" \
        --connect-timeout 5 --max-time 10 || true)
        case "$STATUS_CODE" in
            000)
                echo
                echo "⏳ サービス起動中（ステータス: $STATUS_CODE）"
                ;;
            503)
                echo
                echo "⏳ サービス起動中（ステータス: $STATUS_CODE）"
                ;;
            200)
                echo
                echo "✅ Wazuh Dashboard のWeb画面が応答しています。"
                break
                ;;
            *)
                echo
                echo "⚠️ その他のステータスコード: $STATUS_CODE"
                ;;
        esac

        echo "⏳ ダッシュボード応答待ち... ($i/$MAX_RETRIES)"
        sleep $INTERVAL
        if [[ "$i" -eq "$MAX_RETRIES" ]]; then
            echo "❌ タイムアウト：Web UI にアクセスできませんでした。"
            exit 1
        fi
    done
    
    

    echo "⏳ 初期化が完了するのを待機中（約15秒）..."
    sleep 15

    #手動でwebの起動を待つ
    #ログイン画面の表示を確認したのち次の処理へ進む
    echo "Enterキーを押して適用を実行する"
    read -r

    # securityadmin.sh の実行
    local INDEXER_CONTAINER=$(docker ps --format '{{.Names}}' | grep wazuh.indexer || true)
    if [[ -z "$INDEXER_CONTAINER" ]]; then
        echo "❌ Indexer コンテナが見つかりません。"
        exit 1
    fi

    echo "🔐 securityadmin.sh を使って設定を反映..." 

    docker exec -e INSTALLATION_DIR=/usr/share/wazuh-indexer -e JAVA_HOME=/usr/share/wazuh-indexer/jdk -i "$INDEXER_CONTAINER" bash -c '
    CACERT=$INSTALLATION_DIR/certs/root-ca.pem
    KEY=$INSTALLATION_DIR/certs/admin-key.pem
    CERT=$INSTALLATION_DIR/certs/admin.pem
    /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
        -cd /usr/share/wazuh-indexer/opensearch-security/ \
        -nhnv -cacert $CACERT -cert $CERT -key $KEY -p 9200 -icl
    '
    if [[ $? -ne 0 ]]; then
        echo "❌ securityadmin.sh の実行に失敗しました。" >&2
        exit 1
    fi
    echo "✅ パスワード変更完了！Wazuh Stack が新しい認証情報で動作しています。" >&2
    echo "Wazuh Stack の再起動と設定の反映が完了しました。"
    return 0
}




main() {
    echo "=== Wazuh パスワード変更プロセスを開始 ==="
    for type in "${types[@]}"; do
        echo "🔄 ${type} のパスワードを変更中..."
        local NEW_PASSWORD=$(new_password_make "${ACCOUNT_VARS["$type,account"]}")
        if [[ -z "$NEW_PASSWORD" ]]; then
            echo "❌ ${type} のパスワード変更をスキップします。" >&2
            continue
        fi

        local HASHED_PASSWORD=$(get_password_hash "$NEW_PASSWORD")
        if [[ -z "$HASHED_PASSWORD" ]]; then
            echo "❌ ${type} のハッシュ化に失敗しました。" >&2
            exit 1
        fi
        add_pass_type "$type" "$NEW_PASSWORD" "$HASHED_PASSWORD"

        if ! update "$type"; then
            echo "❌ ${type} の更新に失敗しました。" >&2
            exit 1
        fi
    done
    echo "✅ すべてのパスワードが更新されました。"
}





# ###################################################################################
#　メイン処理
# ###################################################################################
#引数の解析
while getopts "uah" opt; do
    case $opt in
        u) #  ヤムルファイル・ENVの更新 
            echo "パスワード変更の環境設定の更新します"
            echo 
            main
            ;;
        a) # 　コンテナへの反映
            echo "Wazuh Stack の再起動と設定の反映を行います"
            docker_start $URL
            ;;
        h) # ヘルプ
            echo "オプション: [-a:apply] [-u:update]"
            exit 0
            ;;
        \?) # 無効なオプション
            echo "無効なオプションです: -$OPTARG" >&2
            echo "-h: ヘルプを参照してください。"
            exit 1
            ;;
    esac
done

