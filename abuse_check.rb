# frozen_string_literal: true

require 'csv'
require 'net/http'
require 'uri'
require 'json'
require 'ipaddr'
require 'yaml'

class AbuseChecker
  CONFIG_FILE         = File.expand_path('config.yml', __dir__)
  INPUT_CSV           = 'target_ips.csv'
  WHITELIST_CSV       = 'whitelist.csv'
  OUTPUT_CSV          = 'abuse_check_result.csv'
  IP_COLUMN_NAME      = 'ip_address'
  WHITELIST_COL_NAME  = 'ip_or_cidr'
  SUMMARY_STATUS_ORDER = [
    'High Risk',
    'Suspicious',
    'Low Risk',
    'Clean',
    'Whitelisted',
    'Private IP',
    'Invalid IP'
  ].freeze

  # クラスメソッドとして実行可能にする
  def self.run
    new.run
  end

  ##
  # 判定処理のメインフローを実行する（publicインターフェース）
  #
  def run
    # 0. APIキー読み込み（未存在時はテンプレート作成して終了）
    api_key = load_api_key

    # 1. 入力ファイルの検証と読み込み
    rows = load_target_rows
    whitelist = load_whitelist
    puts "ホワイトリスト登録件数: #{whitelist.size} 件"

    unique_ips = rows.map { |r| r[IP_COLUMN_NAME]&.strip }.compact.reject(&:empty?).uniq
    puts "総行数: #{rows.size} 行 / ユニークIP数: #{unique_ips.size} 件"

    # 2. 調査対象の事前仕分け（APIクォータ節約）
    target_ips, results = classify_ips(unique_ips, whitelist)

    puts "  - ホワイトリスト除外: #{results.values.count { |v| v[:status] == 'Whitelisted' }} 件"
    puts "  - プライベートIP除外: #{results.values.count { |v| v[:status] == 'Private IP' }} 件"
    puts "  - 外部API照会対象: #{target_ips.size} 件"

    # 3. API照会実行
    query_abuse_api(target_ips, api_key, results)
    puts "\n照会完了。"

    # 4. 結果をCSVへ出力（悪意スコア降順ソート）
    export_results(results)
    puts "結果を出力しました: #{OUTPUT_CSV}"

    # 5. 判定結果サマリの表示
    display_summary(results)
  end

  private

  ##
  # 設定ファイル (config.yml) からAPIキーを読み込む。
  #
  def load_api_key
    template = <<~YAML
      # AbuseIPDB API Configuration
      # https://www.abuseipdb.com/account/api から取得したAPIキーを設定してください
      api_key: "YOUR_ABUSEIPDB_API_KEY_HERE"
    YAML

    unless File.exist?(CONFIG_FILE)
      File.write(CONFIG_FILE, template)
      File.chmod(0o600, CONFIG_FILE)
      puts "[INFO] 設定ファイルが見つからないため、テンプレートを作成しました: #{CONFIG_FILE}"
      puts "[INFO] ファイルの 'api_key' に有効なAPIキーを設定し、再度実行してください。"
      exit 1
    end

    config = YAML.load_file(CONFIG_FILE) || {}
    api_key = config['api_key']

    if api_key.nil? || api_key.empty? || api_key == 'YOUR_ABUSEIPDB_API_KEY_HERE'
      abort "[ERROR] #{CONFIG_FILE} の 'api_key' が未設定または初期値のままです。有効なキーを設定してください。"
    end

    api_key
  end

  ##
  # 対象IPのCSVを読み込みヘッダーを検証する。
  #
  def load_target_rows
    abort "エラー: 入力ファイル '#{INPUT_CSV}' が見つかりません。" unless File.exist?(INPUT_CSV)

    rows = CSV.read(INPUT_CSV, headers: true)
    unless rows.headers&.include?(IP_COLUMN_NAME)
      abort "エラー: CSVに '#{IP_COLUMN_NAME}' カラムが存在しません。"
    end

    rows
  end

  ##
  # ホワイトリストCSVを読み込み、IPAddrオブジェクトのリストを生成する。
  #
  def load_whitelist
    return [] unless File.exist?(WHITELIST_CSV)

    whitelist = []
    CSV.foreach(WHITELIST_CSV, headers: true) do |row|
      val = row[WHITELIST_COL_NAME]&.strip
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
  # ユニークIPリストをAPI照会対象と除外対象（無効/プライベート/ホワイトリスト）に仕分ける。
  #
  def classify_ips(unique_ips, whitelist)
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

    [target_ips, results]
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
  # 対象IP群に対してAPI照会を行い、結果ハッシュを更新する。
  #
  def query_abuse_api(target_ips, api_key, results)
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
  end

  ##
  # AbuseIPDB API (v2) の /check エンドポイントへ照会する。
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
  # 判定結果を危険度順（スコア降順）にソートしてCSV出力する。
  #
  def export_results(results)
    sorted_results = results.sort_by do |_ip, data|
      score = data[:abuse_score]
      score ? -score : 1
    end

    CSV.open(OUTPUT_CSV, 'w', write_headers: true, headers: %w[ip_address abuse_score status]) do |csv|
      sorted_results.each do |ip, data|
        csv << [ip, data[:abuse_score], data[:status]]
      end
    end
  end

  ##
  # チェック結果のステータス別カウントサマリを標準出力に表示する。
  #
  def display_summary(results)
    counts = Hash.new(0)
    results.each_value { |data| counts[data[:status]] += 1 }

    statuses = SUMMARY_STATUS_ORDER.dup
    counts.each_key do |status|
      statuses << status unless statuses.include?(status)
    end

    puts "\n" + '=' * 40
    puts "判定結果サマリ (対象IP数: #{results.size} 件)"
    puts '-' * 40
    statuses.each do |status|
      count = counts[status]
      next if count.zero? && !SUMMARY_STATUS_ORDER.include?(status)

      puts "  #{status.ljust(22)}: #{count.to_s.rjust(4)} 件"
    end
    puts '=' * 40
  end
end

# -------------------------------------------------------------------
# スクリプト直接実行時のエントリポイント
# -------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  AbuseChecker.run
end
