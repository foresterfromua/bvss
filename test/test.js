let Vulnerability = require('./Vuln.js');
const SCjsonData = require('./json/sc.json');
const WEBjsonData = require('./json/web.json');
const BLjsonData = require('./json/blckchn.json');
const HjsonData = require('./json/hardware.json');

const arr = [];
const ALL_TESTCASES = {
  web_key: WEBjsonData,
  sc_key: SCjsonData,
  bl_key: BLjsonData,
  hardware_key: HjsonData
};

for (let testcase in ALL_TESTCASES) {
  arr.push(ALL_TESTCASES[testcase]); // [ {web}, {sc} ]
}

arr.forEach(app_type => { // {web}
  console.log(`-----------------------------------------
                  NEXT TYPE
----------------------------------------- `)

  app_type.forEach(vuln => { // {vuln = 'Reflected XSS for Primary product'}
    let entity = new Vulnerability(vuln);
    console.log(`Desc: ${entity.desc}\nScore: ${entity.calcScore()}\nBVSS: ${entity.calcBvss()}\n"`);
  });
});