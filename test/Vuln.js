module.exports = class Vulnerability {

  constructor(vuln) {
    this.score = 0
    this.bvss = "None"
    this.desc = vuln["desc"]
    this.base = vuln["base"]
    this.vector = vuln["vector"]
    this.complexity = vuln["complexity"]
    this.privileges = vuln["privileges"]
    this.ui = vuln["ui"]
    this.scope = vuln["scope"]
    this.conf_impact = vuln["conf_impact"]
    this.conf_weight = vuln["conf_weight"]
    this.integ_impact = vuln["integ_impact"]
    this.integ_weight = vuln["integ_weight"]
    this.avail_impact = vuln["avail_impact"]
    this.avail_weight = vuln["avail_weight"]
  }

  calcScore() {
    this.score = this.base + (10 - this.base) * this.vector * this.complexity * this.privileges * this.ui * this.scope * (1 - (1 - this.conf_impact * this.conf_weight) * (1 - this.integ_impact * this.integ_weight) * (1 - this.avail_impact * this.avail_weight))
    if (this.score > 10)
      this.score = 10
    this.score = Math.round(this.score, 1)
    return this.score
  }

  calcBvss() {
    if (this.score >= 9) {
      this.bvss = "Critical"
    } else if (this.score < 9 && this.score >= 7) {
      this.bvss = "High"
    } else if (this.score < 7 && this.score >= 4) {
      this.bvss = "Medium"
    } else {
      this.bvss = "Low"
    }
    return this.bvss
  }

}