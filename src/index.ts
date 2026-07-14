import * as core from "@actions/core";
import {
  attachReleaseAssets,
  getAIBoMGenCommand,
  runAIBoMGenAction,
  runAndFailBuildOnException,
} from "./github/AIBoMGenGithubAction";

const command = core.getInput("command") || "scan";

runAndFailBuildOnException(async () => {
  switch (command) {
    case "scan":
    case "generate":
    case "validate":
    case "completeness":
    case "vuln-scan":
    case "merge":
      await attachReleaseAssets(await runAIBoMGenAction());
      break;
    case "download": {
      const cmd = await getAIBoMGenCommand();
      core.setOutput("cmd", cmd);
      break;
    }
    default:
      core.setFailed(`Unknown command value: ${command}`);
  }
});
