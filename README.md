# tls-cert-watch

外部からTLS 1.3で接続し、実際に配信されるRSA・ECDSA証明書を個別に検査する小さなGo CLIです。Let's Encryptの6日間証明書など、短命証明書の更新失敗の検出を目的としています。状態の保存・通知の重複排除・外部API・CTログは使用しません。

## 監視の仕組み

ホストと鍵種別ごとに、別プロセスの `openssl s_client` で新しいハンドシェイクを行います。SNIを明示し、`-tls1_3 -sigalgs` で提示する署名アルゴリズムを制限します。

- RSA: `rsa_pss_rsae_sha256/384/512` と `rsa_pss_pss_sha256/384/512`
- ECDSA: `ecdsa_secp256r1_sha256`、`ecdsa_secp384r1_sha384`、`ecdsa_secp521r1_sha512`

通常のTLS接続ではクライアントの提示内容によって選ばれる証明書が変わり、一方の証明書の更新失敗を見逃す場合があります。そのためRSAとECDSAを独立して取得します。ECDSAはP-256に限定していません。Go標準の `crypto/tls` はクライアントの署名アルゴリズムを自由に指定できないため、取得にはOpenSSLを使用します。

OpenSSLの終了コード、TLS 1.3の接続成立と暗号スイート、`Verify return code` を確認します。検証失敗時にも証明書を取得するため、`-verify_return_error` は付けず、検証結果が非ゼロ・欠落なら必ず異常とします。終了コード0やPEMの存在だけでは成功と判定しません。標準入力をEOFにして終了し、DNS解決・接続・ハンドシェイクを含むプロセス全体にタイムアウトを設定します。

`-showcerts` のPEMをGoの `crypto/x509` で解析し、公開鍵アルゴリズム、ホスト名、信頼チェーン、サーバー認証用途、有効期間を再検証します。公開鍵アルゴリズムは証明書自体の署名アルゴリズムと区別します。通常はOSの信頼ストアを使い、`-ca-file` 指定時はOpenSSLにそのCAファイルを渡し、Goでは指定CAだけを信頼します。中間証明書はサーバーが配信したチェーンを使用します。

検査失敗後も次の鍵種別・ホストへ進みます。正常・異常のどちらも、ホスト・ポート・要求した鍵種別・実際の公開鍵種別・NotBefore・有効期限・残り時間をログに出します。取得できなかった情報は「不明」と表示します。検証失敗時も取得できた証明書情報を残します。

## 設定

`targets.json` を実際の監視対象に書き換えてください。同梱の `example.com` は形式を示すサンプルであり、両鍵種別が取得できることを保証しません。

```json
[
  {
    "host": "www.example.com",
    "key_types": ["RSA", "ECDSA"]
  },
  {
    "host": "other.example.com",
    "port": 8443,
    "key_types": ["ECDSA"]
  }
]
```

`host` はスキームやポートを含まないホスト名またはIPアドレスです。国際化ドメインはASCIIのPunycode表記を使ってください。`port` の省略・0は443です。`key_types` は必須で、大文字の `RSA` / `ECDSA` を重複なく指定します。両方を配信するサイトには必ず両方を指定してください。片方しか取得できなくても異常です。空設定や未知のフィールドも設定エラーにします。

## 判定基準

| 有効期限までの残り時間 | 判定 |
| --- | --- |
| 48時間以上 | 正常 |
| 24時間以上48時間未満 | 警告 |
| 0時間超24時間未満 | 緊急 |
| 0時間以下 | 異常（期限切れ） |

残り時間は各検査の実行時刻と `NotAfter` の差で判断し、日数への丸めは行いません。48時間ちょうどは正常、24時間ちょうどは警告です。未発効・不正な有効期間、ホスト名・チェーン・鍵種別の不一致、証明書欠落、接続失敗、タイムアウト、OpenSSLの実行失敗も異常です。証明書の検証に失敗した場合は、期限の判定にかかわらず異常です。

警告・緊急・異常はすべてSlack通知と終了コード1の対象です。全検査が正常なら通知せず0で終了します。

## ローカル実行

Go 1.24以上、TLS 1.3対応OpenSSL（OpenSSL 3推奨）、信頼できるCAストアを用意します。Goの外部モジュール依存はありません。

```sh
go build -o tls-cert-watch .

# Slack通知なしで検査する（異常時の終了コードは1）
./tls-cert-watch -config targets.json -no-slack

# macOSの標準opensslはLibreSSLの場合があるため、Homebrew版を明示できる
./tls-cert-watch -config targets.json -no-slack \
  -openssl /opt/homebrew/opt/openssl@3/bin/openssl
```

Slack通知には [notify_slack](https://github.com/catatsuy/notify_slack) を使用します。[v0.5.16のRelease](https://github.com/catatsuy/notify_slack/releases/tag/v0.5.16) からOS・CPUに対応するバイナリを取得し、PATHに配置してください。

```sh
export NOTIFY_SLACK_TOKEN='...'
export NOTIFY_SLACK_CHANNEL_ID='...'
./tls-cert-watch -config targets.json
```

主なオプション（全体は `-help`）：

| オプション | 既定値 | 用途 |
| --- | --- | --- |
| `-config` | `targets.json` | 設定ファイル |
| `-openssl` | `openssl` | OpenSSLの実行ファイル |
| `-timeout` | `20s` | 1検査のタイムアウト |
| `-notify-slack` | `notify_slack` | 通知CLIの実行ファイル |
| `-notify-timeout` | `1m` | 集約通知のタイムアウト |
| `-ca-file` | 未指定 | 独自CAのPEMファイル |
| `-no-slack` | false | ローカル検査用に通知を省略 |

異常がある場合だけ、全対象の異常を1つのテキストファイルとして `notify_slack -c /dev/null -snippet -snippet-type text` に渡します。ホスト名、RSA/ECDSA、異常内容、有効期限、残り時間を含みます。設定読み込み失敗など、監視を開始できない場合も通知を試みます。認証情報はコマンド引数やログに出しません。

通知完了を待ってから異常終了します。通知CLIの不在、Secrets未設定、Slackへの投稿失敗・タイムアウトも終了コード1です。正常時には通知CLIやSlack認証情報は不要です。状態を持たないため、異常が続く限り実行ごとに通知します。

## GitHub Actions

1. `targets.json` を実際の監視対象に更新してデフォルトブランチへ反映します。
2. Slack AppのBot Tokenに `files:write` を付与し、ワークスペースへインストールして投稿先チャンネルへ招待します。
3. リポジトリの **Settings → Secrets and variables → Actions** に次のSecretsを登録します。

| Secret | 内容 |
| --- | --- |
| `NOTIFY_SLACK_TOKEN` | Slack Bot Token |
| `NOTIFY_SLACK_CHANNEL_ID` | 投稿先チャンネルのID（名前ではない） |

`.github/workflows/watch.yml` はUbuntu runnerで、UTCの00:17 / 03:17 / 06:17 / 09:17 / 12:17 / 15:17 / 18:17 / 21:17（日本時間も3時間ごとの17分）に実行します。Actionsタブの **TLS certificate watch → Run workflow** で手動実行できます。

OpenSSLとCA証明書をインストールし、バージョンとSHA-256を固定した `notify_slack` を配置します。権限は `contents: read` だけで、GitHubへの書き込みや状態用ブランチ、DB、Heartbeat、他の監視サービスは不要です。ジョブ全体のタイムアウトは15分、通常の1検査は20秒です。対象を大量に追加する場合は検査数とタイムアウトの合計がジョブ上限内に収まるよう調整してください。ジョブ上限による強制終了やrunner/ツール準備自体の障害では、CLIからのSlack通知まで到達できない場合があります。

GitHub Actionsの定期実行には遅延や実行漏れの可能性があります。定期実行はデフォルトブランチ上で動作し、公開リポジトリは長期間の操作がないとスケジュールが無効になる場合もあります。Actionsの実行履歴とスケジュールの有効状態を定期的に確認してください。厳密な3時間間隔の実行を保証する仕組みではありません。

通知方式は [rss-curator](https://github.com/catatsuy/rss-curator) を参考にしています。

## 開発・テスト

```sh
go test ./...
go vet ./...

# 別のOpenSSLで統合テストする場合
TEST_OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl go test ./...
```

単体テストでは証明書とCAをその場で生成し、OpenSSL出力を模擬します。RSA/ECDSAの正常・片方だけの期限切れ・取得失敗、鍵種別・ホスト名・チェーンの不一致、未発効、48時間/24時間境界、実行・接続失敗、複数ホストの部分失敗、通知の集約と失敗を検証します。

統合テストではループバックのTLS 1.3サーバーがClientHelloに応じて証明書を出し分け、実際のOpenSSLでRSAとECDSA（P-256 / P-384 / P-521）を別々に取得して検証します。SNI、接続拒否、応答しないTCPサーバーに対するタイムアウトも確認します。外部ネットワークやSlackは呼びません。対応するOpenSSLが未インストールの場合は統合テストをスキップします。macOSでは標準LibreSSLの代わりにHomebrewのOpenSSL 3も探します。ループバックへのbindが許可された環境で実行してください。CIではOpenSSLがあるUbuntu runnerで全テストを実行します。
