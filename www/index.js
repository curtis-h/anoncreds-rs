// import * as anoncreds from "wasm-pkg";
// import wasm from "wasm-pkg/anoncreds_bg.wasm";
import * as anoncreds from "../pkg";
import wasm from "../pkg/anoncreds_bg.wasm";

(async () => {
  await anoncreds.default(wasm());
  
  window.anoncreds = anoncreds;
  window.wasm = anoncreds;
  anoncreds.anoncredsSetDefaultLogger();
  // console.log("READY");
})()
