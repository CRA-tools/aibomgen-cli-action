import {
  attachReleaseAssets,
  runAIBoMGenAction,
  runAndFailBuildOnException,
} from "./github/AIBoMGenGithubAction";

runAndFailBuildOnException(async () => attachReleaseAssets(await runAIBoMGenAction()));
