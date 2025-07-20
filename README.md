# 🔐 Wazuh Pass Wizard

Wazuh（Docker Compose構成）で使用される `.env` ファイル内のユーザーパスワードを対話的に変更・適用するシェルスクリプトです。

## 📦 特徴

- `.env` ファイルに定義された各種パスワード（例: `INDEXER_PASSWORD`, `DASHBOARD_PASSWORD` など）を安全に更新
- `-u` オプションで `.env` のみを変更（更新前に中身の確認あり）
- `-a` オプションで Docker コンテナに設定を反映（再起動付き）
- 対話形式のシンプルなCLIウィザード

## 🧾 対応環境

- Wazuh 4.12.0 以降
- Docker Compose 構成
- Ubuntu 22.04 / 24.04（他のディストリビューションでも動作可能）

## 🚀 使い方

### 1. スクリプトの設置

Docker Compose の `docker-compose.yml` ファイルと同じディレクトリに `wazuh-passchange.sh` を配置してください。
