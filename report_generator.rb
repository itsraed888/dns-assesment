require 'csv'
require_relative './utils/dns_lookup'
require_relative 'dns_analyzer'
require 'time'

include Utils

def calculate_risk_score_and_details(spf:, dmarc:, dnssec:, ttl:, ptr_exists:, ptr_matches:, apex_cname:, recursion:)
  score = 0.0
  issues = []

  unless spf
    score += 3.0
    issues << ["Missing SPF", 3.0]
  end
  unless dmarc
    score += 2.5
    issues << ["Missing DMARC", 2.5]
  end
  unless dnssec
    score += 4.0
    issues << ["Missing DNSSEC", 4.0]
  end
  unless ptr_exists
    score += 1.0
    issues << ["Missing PTR", 1.0]
  end
  unless ptr_matches
    score += 1.5
    issues << ["PTR mismatch", 1.5]
  end
  if apex_cname
    score += 5.0
    issues << ["Apex CNAME present", 5.0]
  end
  if recursion
    score += 4.0
    issues << ["NS recursion enabled", 4.0]
  end
  if ttl.is_a?(Integer) && ttl < 60 && ttl > 86400
    score += 0.5
    issues << ["Low TTL", 0.5]
  end

  risk_level =
    if score >= 13 then "High"
    elsif score >= 6 then "Medium"
    else "Low"
    end

  [score, risk_level, issues]
end

def generate_csv_report(domain, wordlist_path)
  spf_result = check_spf(domain)
  dmarc_result = check_dmarc(domain)
  dnssec_result = !dnssec_missing?(domain)
  ttl = check_ttl(domain)
  ptr_result = check_ptr(domain)
  recursive_ns = check_recursion(domain)
  apex_cname = apex_has_cname?(domain)
  nameservers = get_nameservers(domain)

  ptr_exists = !ptr_result.nil?
  ptr_matches = ptr_result.to_s.include?(domain)

  score, risk_level, issues = calculate_risk_score_and_details(
    spf: spf_result,
    dmarc: dmarc_result,
    dnssec: dnssec_result,
    ttl: ttl,
    ptr_exists: ptr_exists,
    ptr_matches: ptr_matches,
    apex_cname: apex_cname,
    recursion: !recursive_ns.empty?
  )

  timestamp = Time.now.strftime("%Y-%m-%d %H:%M")
  CSV.open("report.csv", "w") do |csv|
    csv << ["======================== DOMAIN ANALYSIS REPORT ========================"]
    csv << ["Domain:", domain]
    csv << ["Generated:", timestamp]
    csv << []
    csv << ["---------------------------- DNS STATUS -------------------------------"]
    csv << ["SPF", "DMARC", "DNSSEC", "TTL", "PTR Exists", "PTR Matches", "Apex CNAME", "NS Recursion"]
    csv << [spf_result, dmarc_result, dnssec_result, ttl, ptr_exists, ptr_matches, apex_cname, !recursive_ns.empty?]
    csv << []
    csv << ["------------------------- RISK SCORING --------------------------------"]
    csv << ["Risk Score", "Risk Level"]
    csv << [score, risk_level]
    csv << []
    csv << ["---------------------- Misconfiguration Details -----------------------"]
    csv << ["Type", "Severity"]
    issues.each { |type, severity| csv << [type, severity] }
  end

  puts "✅ Report saved to report.csv"
end
