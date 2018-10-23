var CVSS = {};

CVSS.CVSSVersionIdentifier = "CVSS:3.0";

CVSS.Weight = {
  B: {
    S: 8,
    L: 6,
    N: 0
  },
  AV: {
    N: 1,
    P: 0.5
  },
  AC: {
    H: 0.8,
    L: 1
  },
  PR: {
    N: 1,
    R: 0.7,
  },
  UI: {
    N: 1,
    R: 0.7
  },
  S: {
    U: 1,
    C: 1.5
  },
  CIA: {
    N: 0,
    L: 0.3,
    M: 0.66,
    H: 1
  },
  CIAI: {
    L: 0.33,
    M: 0.66,
    H: 1
  }
};


CVSS.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
  },
  {
    name: "Low",
    bottom: 0.1,
    top: 3.9
  },
  {
    name: "Medium",
    bottom: 4.0,
    top: 6.9
  },
  {
    name: "High",
    bottom: 7.0,
    top: 8.9
  },
  {
    name: "Critical",
    bottom: 9.0,
    top: 10.0
  }
];

CVSS.calculateCVSSFromMetrics = function (
  Base, AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope,
  Confidentiality, Integrity, Availability, ConfidentialityImpact, IntegrityImpact, AvailabilityImpact) {

  var badMetrics = [];

  if (typeof Base === "undefined" || Base === "") {
    badMetrics.push("B");
  }
  if (typeof AttackVector === "undefined" || AttackVector === "") {
    badMetrics.push("AV");
  }
  if (typeof AttackComplexity === "undefined" || AttackComplexity === "") {
    badMetrics.push("AC");
  }
  if (typeof PrivilegesRequired === "undefined" || PrivilegesRequired === "") {
    badMetrics.push("PR");
  }
  if (typeof UserInteraction === "undefined" || UserInteraction === "") {
    badMetrics.push("UI");
  }
  if (typeof Scope === "undefined" || Scope === "") {
    badMetrics.push("S");
  }
  if (typeof Confidentiality === "undefined" || Confidentiality === "") {
    badMetrics.push("C");
  }
  if (typeof Integrity === "undefined" || Integrity === "") {
    badMetrics.push("I");
  }
  if (typeof Availability === "undefined" || Availability === "") {
    badMetrics.push("A");
  }
  if (typeof ConfidentialityImpact === "undefined" || ConfidentialityImpact === "") {
    badMetrics.push("CI");
  }
  if (typeof IntegrityImpact === "undefined" || IntegrityImpact === "") {
    badMetrics.push("II");
  }
  if (typeof AvailabilityImpact === "undefined" || AvailabilityImpact === "") {
    badMetrics.push("AI");
  }

  if (badMetrics.length > 0) {
    return {
      success: false,
      errorType: "MissingBaseMetric",
      errorMetrics: badMetrics
    };
  }

  var B = Base;
  var AV = AttackVector;
  var AC = AttackComplexity;
  var PR = PrivilegesRequired;
  var UI = UserInteraction;
  var S = Scope;
  var C = Confidentiality;
  var I = Integrity;
  var A = Availability;
  var CI = ConfidentialityImpact;
  var II = IntegrityImpact;
  var AI = AvailabilityImpact;

  if (!CVSS.Weight.B.hasOwnProperty(B)) {
    badMetrics.push("B");
  }
  if (!CVSS.Weight.AV.hasOwnProperty(AV)) {
    badMetrics.push("AV");
  }
  if (!CVSS.Weight.AC.hasOwnProperty(AC)) {
    badMetrics.push("AC");
  }
  if (!CVSS.Weight.PR.hasOwnProperty(PR)) {
    badMetrics.push("PR");
  }
  if (!CVSS.Weight.UI.hasOwnProperty(UI)) {
    badMetrics.push("UI");
  }
  if (!CVSS.Weight.S.hasOwnProperty(S)) {
    badMetrics.push("S");
  }
  if (!CVSS.Weight.CIA.hasOwnProperty(C)) {
    badMetrics.push("C");
  }
  if (!CVSS.Weight.CIA.hasOwnProperty(I)) {
    badMetrics.push("I");
  }
  if (!CVSS.Weight.CIA.hasOwnProperty(A)) {
    badMetrics.push("A");
  }
  if (!CVSS.Weight.CIAI.hasOwnProperty(CI)) {
    badMetrics.push("CI");
  }
  if (!CVSS.Weight.CIAI.hasOwnProperty(II)) {
    badMetrics.push("II");
  }
  if (!CVSS.Weight.CIAI.hasOwnProperty(AI)) {
    badMetrics.push("AI");
  }

  if (badMetrics.length > 0) {
    return {
      success: false,
      errorType: "UnknownMetricValue",
      errorMetrics: badMetrics
    };
  }
  // GATHER WEIGHTS FOR ALL METRICS

  var metricWeightAV = CVSS.Weight.AV[AV];
  var metricWeightAC = CVSS.Weight.AC[AC];
  var metricWeightPR = CVSS.Weight.PR[PR];
  var metricWeightUI = CVSS.Weight.UI[UI];
  var metricWeightS = CVSS.Weight.S[S];
  var metricWeightC = CVSS.Weight.CIA[C];
  var metricWeightI = CVSS.Weight.CIA[I];
  var metricWeightA = CVSS.Weight.CIA[A];

  var metricWeightB = CVSS.Weight.B[B];

  var metricWeightCI = CVSS.Weight.CIAI[CI];
  var metricWeightII = CVSS.Weight.CIAI[II];
  var metricWeightAI = CVSS.Weight.CIAI[AI];
  // CALCULATE THE CVSS BASE SCORE

  var baseScore;
  baseScore = CVSS.roundUp1(metricWeightB + (10 - metricWeightB) * metricWeightAV * metricWeightAC * metricWeightPR * metricWeightUI * metricWeightS * (1 - (1 - metricWeightC * metricWeightCI) * (1 - metricWeightI * metricWeightII) * (1 - metricWeightA * metricWeightAI)));
  console.log(baseScore);
  if (baseScore > 10) {
    baseScore = 10;
  }
  // self.score = self.base + (10 - self.base) * self.vector * self.complexity * self.privileges * self.ui * self.scope * \
  // (1 - (1 - self.conf_impact * self.conf_weight) * (1 - self.integ_impact * self.integ_weight) * (1 - self.avail_impact * self.avail_weight))
  return {
    success: true,
    baseMetricScore: baseScore.toFixed(1),
    baseSeverity: CVSS.severityRating(baseScore.toFixed(1)),
  };
};

CVSS.calculateCVSSFromVector = function (vectorString) {

  var metricValues = {
    B: undefined,
    AV: undefined,
    AC: undefined,
    PR: undefined,
    UI: undefined,
    S: undefined,
    C: undefined,
    I: undefined,
    A: undefined,
    CI: undefined,
    II: undefined,
    AI: undefined
  };

  var badMetrics = [];

  var metricNameValue = vectorString.substring(CVSS.CVSSVersionIdentifier.length).split("/");

  for (var i in metricNameValue) {
    if (metricNameValue.hasOwnProperty(i)) {

      var singleMetric = metricNameValue[i].split(":");

      if (typeof metricValues[singleMetric[0]] === "undefined") {
        metricValues[singleMetric[0]] = singleMetric[1];
      } else {
        badMetrics.push(singleMetric[0]);
      }
    }
  }

  if (badMetrics.length > 0) {
    return {
      success: false,
      errorType: "MultipleDefinitionsOfMetric",
      errorMetrics: badMetrics
    };
  }

  return CVSS.calculateCVSSFromMetrics(
    metricValues.B, metricValues.AV, metricValues.AC, metricValues.PR, metricValues.UI, metricValues.S,
    metricValues.C, metricValues.I, metricValues.A, metricValues.CI, metricValues.II, metricValues.AI);
};

CVSS.roundUp1 = function (d) {
  return Math.ceil(d * 10) / 10;
};

CVSS.severityRating = function (score) {
  var severityRatingLength = CVSS.severityRatings.length;

  var validatedScore = Number(score);

  if (isNaN(validatedScore)) {
    return validatedScore;
  }

  for (var i = 0; i < severityRatingLength; i++) {
    if (score >= CVSS.severityRatings[i].bottom && score <= CVSS.severityRatings[i].top) {
      return CVSS.severityRatings[i].name;
    }
  }

  return undefined;
};