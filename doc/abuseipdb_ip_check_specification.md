# AbuseIPDB APIを活用した不審アクセスIP判定スクリプト仕様書

調査対象のIPアドレス一覧CSVから、AbuseIPDB API (v2) を用いて不正スコア（`abuseConfidenceScore`）を照会し、最小限の判定結果（IP・スコア・ステータス）を出力するRubyスクリプトの仕様および実装まとめです。

---

## 1. 概要と機能要件

* **必要最小限の入出力**: 調査対象IPとホワイトリストのみを入力とし、結果は `ip_address`, `abuse_score`, `status` の3項目に絞って出力。
* **APIクォータ保護**: 同一IPの重複排除、プライベートIP/ループバックアドレスの自動スキップを実施。
* **ホワイトリスト照会**: 自社IPやVPNなどのCIDR範囲（`/24` 等）を外部CSVから読み込み、API照会前に除外（APIリクエスト消費ゼロ）。
* **安全な設定管理**: スクリプトと同階層の `config.yml` からAPIキーを読み込み。ファイル未存在時はテンプレートを自動生成（権限 `0600`）して設定を案内。
* **外部gem非依存**: Ruby標準ライブラリ（`csv`, `net/http`, `uri`, `ipaddr`, `json`, `yaml`）のみで動作。
* **危険度順ソート**: 判定結果を悪意スコア降順（高リスクが先頭）でソートして出力。

---

## 2. APIパラメータの選定理由 (`maxAgeInDays: 90`)

AbuseIPDB APIの照会パラメータ `maxAgeInDays`（過去何日間の報告を対象とするか）には **`90`** を指定しています。

1. **間欠的・低頻度スキャンの検知漏れ防止**
   * デフォルトの `30` 日では、検知回避のために数週間〜1ヶ月以上のインターバルを空けて巡回してくるボットネットやスキャナーを取りこぼすリスクがあります。
2. **動的IP（DHCP）の巻き添え誤検知防止**
   * 180日や365日など長期に設定しすぎると、IP再割り当て後の無害な一般ユーザーを誤判定するリスク（フォールスポジティブ）が高まります。90日はそのバランスが最も取れた上限ラインです。
3. **AbuseIPDB標準表示との整合**
   * AbuseIPDBのWebコンソール標準検索の対象期間（90日）と一致させることで、手動確認結果との乖離を防ぎます。

---

## 3. 入出力フォーマット

### 設定ファイル: `config.yml` (未存在時は自動生成)
`.gitignore` に登録してリポジトリ管理から除外。初回実行時にテンプレートが権限 `0600`（所有者のみ読み書き可）で自動生成されます。
```yaml
# AbuseIPDB API Configuration
# https://www.abuseipdb.com/account/api から取得したAPIキーを設定してください
api_key: "YOUR_ABUSEIPDB_API_KEY_HERE"
```

### 入力: `target_ips.csv` (調査対象IPリスト)
ヘッダー行とIPアドレスのみの1列構成。
```csv
ip_address
185.220.101.5
118.25.6.39
203.0.113.15
198.51.100.88
192.168.1.50
invalid-ip-string
```

### 入力: `whitelist.csv` (除外ホワイトリスト)
単一IPおよびCIDRブロックに対応。ファイルが存在しない場合は除外なしで処理されます。
```csv
ip_or_cidr
203.0.113.15
198.51.100.0/24
```

### 出力: `abuse_check_result.csv` (判定結果)
危険度の高い順（悪意スコア降順）にソートされた最小限の3列構成。高リスクIPが先頭に並ぶため、即座に対処・分析が可能です。
```csv
ip_address,abuse_score,status
185.220.101.5,100,High Risk
118.25.6.39,85,High Risk
203.0.113.15,0,Whitelisted
198.51.100.88,0,Whitelisted
192.168.1.50,0,Private IP
invalid-ip-string,,Invalid IP
```

---

## 4. スコアとステータスの判定基準

| ステータス (`status`) | スコア範囲 (`abuse_score`) | 判定リスク / 理由 |
| :--- | :--- | :--- |
| **High Risk** | **80% 〜 100%** | 極めて危険（即時ブロック推奨） |
| **Suspicious** | **20% 〜 79%** | 要警戒・不審なアクティビティあり |
| **Low Risk** | **1% 〜 19%** | 低リスク（軽微な過去報告など） |
| **Clean** | **0%** | 悪意報告なし（正常） |
| **Whitelisted** | **0%** | ホワイトリストによる除外（API照会スキップ） |
| **Private IP** | **0%** | プライベート/ループバックIP（API照会スキップ） |
| **Invalid IP** | *(なし)* | IPアドレス形式エラー（API照会スキップ） |
| **API Error** | *(なし)* | 通信エラーまたはレートリミット到達 |

---

## 5. 出力ソート仕様（危険度順）

管理者が高リスクIPを即座に特定・対処できるように、出力CSVは**危険度の高い順（悪意スコアの降順）にソート**して出力します。

1. **最優先（高リスク〜低リスク）**: 
   * `abuse_score` の降順（`100` → `1`）でソートし、最も危険なIPが先頭に並びます。
2. **中間（無害・除外IP）**: 
   * スコアが `0` のIP（`Clean`, `Whitelisted`, `Private IP`）が続きます。
3. **末尾（未取得・エラー）**: 
   * スコアが存在しない `nil` のIP（`Invalid IP`, `API Error`）はファイルの末尾に配置されます。

---

## 6. スクリプト実装コード (`abuse_check.rb`)

```ruby
require 'csv'
require 'net/http'
require 'uri'
require 'json'
require 'ipaddr'
require 'yaml'

# 設定定数
CONFIG_FILE         = File.expand_path('config.yml', __dir__)
INPUT_CSV           = 'target_ips.csv'
WHITELIST_CSV       = 'whitelist.csv'
OUTPUT_CSV          = 'abuse_check_result.csv'
IP_COLUMN_NAME      = 'ip_address'
WHITELIST_COL_NAME  = 'ip_or_cidr'

##
# 設定ファイル (config.yml) からAPIキーを読み込む。
# ファイルが存在しない場合はテンプレートを自動生成（権限0600）し、入力を促して終了する。
#
# @param config_path [String] 設定ファイルのパス
# @return [String] 有効なAbuseIPDB APIキー
#
def load_api_key(config_path)
  template = <<~YAML
    # AbuseIPDB API Configuration
    # https://www.abuseipdb.com/account/api から取得したAPIキーを設定してください
    api_key: "YOUR_ABUSEIPDB_API_KEY_HERE"
  YAML

  unless File.exist?(config_path)
    File.write(config_path, template)
    File.chmod(0600, config_path)
    puts "[INFO] 設定ファイルが見つからないため、テンプレートを作成しました: #{config_path}"
    puts "[INFO] ファイルの 'api_key' に有効なAPIキーを設定し、再度実行してください。"
    exit 1
  end

  config = YAML.load_file(config_path) || {}
  api_key = config['api_key']

  if api_key.nil? || api_key.empty? || api_key == 'YOUR_ABUSEIPDB_API_KEY_HERE'
    abort "[ERROR] #{config_path} の 'api_key' が未設定または初期値のままです。有効なキーを設定してください。"
  end

  api_key
end

##
# ホワイトリストCSVを読み込み、IPAddrオブジェクトのリストを生成する。
#
# @param file_path [String] ホワイトリストCSVパス
# @param col_name [String] 列名
# @return [Array<IPAddr>]
#
def load_whitelist(file_path, col_name)
  return [] unless File.exist?(file_path)

  whitelist = []
  CSV.foreach(file_path, headers: true) do |row|
    val = row[col_name]&.strip
    next if val.nil? || val.empty?

    begin
      whitelist << IPAddr.new(val)
    rescue IPAddr::InvalidAddressError => e
      warn "ホワイトリストの無効なIP/CIDRをスキップ: #{val} (#{e.message})"
    end
  end
  whitelist
end

##
# IPアドレスがホワイトリストに含まれるか判定する。
#
def whitelisted?(ip_obj, whitelist)
  whitelist.any? { |allowed| allowed.include?(ip_obj) }
end

##
# IPアドレスがプライベートまたはループバックか判定する。
#
def private_ip?(ip_obj)
  ip_obj.private? || ip_obj.loopback?
end

##
# AbuseIPDBのスコアからステータス文字列を判定する。
#
def determine_status(score)
  case score
  when 80..100 then 'High Risk'
  when 20..79  then 'Suspicious'
  when 1..19   then 'Low Risk'
  when 0       then 'Clean'
  else              'Unknown'
  end
end

##
# AbuseIPDB API (v2) の /check エンドポイントへ照会する。
#
# @param ip [String] 対象IP
# @param api_key [String] APIキー
# @return [Integer, Symbol, nil] 悪意スコア (0-100), :rate_limit, または nil (エラー時)
#
def check_ip(ip, api_key)
  uri = URI('https://api.abuseipdb.com/api/v2/check')
  uri.query = URI.encode_www_form(ipAddress: ip, maxAgeInDays: '90', verbose: 'false')

  request = Net::HTTP::Get.new(uri)
  request['Accept'] = 'application/json'
  request['Key'] = api_key

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = true
  http.read_timeout = 10
  http.open_timeout = 10

  response = http.request(request)

  case response.code.to_i
  when 200
    data = JSON.parse(response.body)['data'] || {}
    data['abuseConfidenceScore']
  when 429
    warn "\nAPIリクエストの上限（レートリミット）に達しました。"
    :rate_limit
  else
    warn "\nAPIエラー [#{ip}]: HTTP #{response.code}"
    nil
  end
rescue StandardError => e
  warn "\n通信エラー [#{ip}]: #{e.message}"
  nil
end

# -------------------------------------------------------------------
# メイン処理
# -------------------------------------------------------------------

# 0. APIキー読み込み（未存在時はテンプレート作成して終了）
api_key = load_api_key(CONFIG_FILE)

# 1. 入力ファイルの検証と読み込み
abort "エラー: 入力ファイル '#{INPUT_CSV}' が見つかりません。" unless File.exist?(INPUT_CSV)

rows = CSV.read(INPUT_CSV, headers: true)
unless rows.headers&.include?(IP_COLUMN_NAME)
  abort "エラー: CSVに '#{IP_COLUMN_NAME}' カラムが存在しません。"
end

whitelist = load_whitelist(WHITELIST_CSV, WHITELIST_COL_NAME)
puts "ホワイトリスト登録件数: #{whitelist.size} 件"

unique_ips = rows.map { |r| r[IP_COLUMN_NAME]&.strip }.compact.uniq
puts "総行数: #{rows.size} 行 / ユニークIP数: #{unique_ips.size} 件"

# 2. 調査対象の事前仕分け（APIクォータ節約）
target_ips = []
results = {}

unique_ips.each do |ip_str|
  begin
    ip_obj = IPAddr.new(ip_str)
  rescue IPAddr::InvalidAddressError
    results[ip_str] = { abuse_score: nil, status: 'Invalid IP' }
    next
  end

  if private_ip?(ip_obj)
    results[ip_str] = { abuse_score: 0, status: 'Private IP' }
  elsif whitelisted?(ip_obj, whitelist)
    results[ip_str] = { abuse_score: 0, status: 'Whitelisted' }
  else
    target_ips << ip_str
  end
end

puts "  - ホワイトリスト除外: #{results.values.count { |v| v[:status] == 'Whitelisted' }} 件"
puts "  - プライベートIP除外: #{results.values.count { |v| v[:status] == 'Private IP' }} 件"
puts "  - 外部API照会対象: #{target_ips.size} 件"

# 3. API照会実行
target_ips.each_with_index do |ip, index|
  print "\r照会中... (#{index + 1}/#{target_ips.size}): #{ip}"
  score = check_ip(ip, api_key)

  if score == :rate_limit
    results[ip] = { abuse_score: nil, status: 'API Error (Rate Limit)' }
    break
  elsif score.nil?
    results[ip] = { abuse_score: nil, status: 'API Error' }
  else
    results[ip] = { abuse_score: score, status: determine_status(score) }
  end

  sleep 0.2 # レート制限保護
end
puts "\n照会完了。"

# 4. 結果をCSVへ出力（悪意スコア降順ソート）
sorted_results = results.sort_by do |_ip, data|
  score = data[:abuse_score]
  score ? -score : 1
end

CSV.open(OUTPUT_CSV, 'w', write_headers: true, headers: %w[ip_address abuse_score status]) do |csv|
  sorted_results.each do |ip, data|
    csv << [ip, data[:abuse_score], data[:status]]
  end
end

puts "結果を出力しました: #{OUTPUT_CSV}"
```
