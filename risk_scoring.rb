# risk_scoring.rb
class RiskScoring
  def self.calculate(issues)
    total = issues.map { |i| i[:severity] }.sum

    level =
      if total >= 8
        "High"
      elsif total >= 4
        "Medium"
      else
        "Low"
      end

    { score: total, level: level }
  end
end
