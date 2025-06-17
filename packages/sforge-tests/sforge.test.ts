import { beforeAll, afterAll, describe, test, expect } from "bun:test"
import {
  runProcess,
  waitForProcessExit,
  type RunProcessOptions,
} from "seismic-viem-tests"
import { repos, type Repo } from "./repos"
import path from "path"
import fs from "fs/promises"

let sforgeBinary: string = process.env.SFORGE_BINARY || "sforge"

type CommandOutput = {
  stdout: Buffer
  stderr: Buffer
  exitCode: number | null
}

type TestOutput = {
  repo: string
  success: boolean
  error?: string
  build?: CommandOutput
  test?: CommandOutput
}

const getCodeLocation = (): string => {
  if (process.env.CODE_PATH) {
    return process.env.CODE_PATH
  }
  return new URL("../../..", import.meta.url).pathname
}

const getRepoLocation = (repo: Repo): string =>
  path.join(getCodeLocation(), repo.repo)

const getRepoContractsPath = (repo: Repo): string =>
  path.join(getRepoLocation(repo), repo.contracts || "")

const ensurePathExists = async (path: string): Promise<void> => {
  const exists = await fs.exists(path)
  if (!exists) {
    throw new Error(`Path ${path} does not exist`)
  }
}

const spawn = async (
  command: string,
  options: RunProcessOptions
): Promise<CommandOutput> => {
  const childProcess = await runProcess(command, options)
  // Start collecting output immediately
  let stdoutChunks: Buffer[] = []
  let stderrChunks: Buffer[] = []

  if (childProcess.stdout) {
    childProcess.stdout.on("data", (chunk) => {
      stdoutChunks.push(chunk)
    })
  }

  if (childProcess.stderr) {
    childProcess.stderr.on("data", (chunk) => {
      stderrChunks.push(chunk)
    })
  }

  // Wait for process to complete
  await waitForProcessExit(childProcess)
  return {
    stdout: Buffer.concat(stdoutChunks),
    stderr: Buffer.concat(stderrChunks),
    exitCode: childProcess.exitCode,
  }
}

/**
 * Ensures a repo exists in the code location.
 * @param repo - The repo to ensure exists.
 * @returns True if the repo already exists, false if it was cloned.
 * @throws If the repo fails to be cloned.
 */
const ensureRepoExists = async (repo: Repo): Promise<boolean> => {
  const repoLocation = getRepoLocation(repo)
  const repoExists = await fs.exists(repoLocation)
  if (repoExists) {
    return true
  }
  if (!repo.clone) {
    return false
  }
  console.warn(`Repo ${repo.repo} does not exist. Cloning...`)
  await spawn("git", {
    args: ["clone", repo.remote],
    cwd: getCodeLocation(),
    stdio: ["inherit", "pipe", "pipe"],
  })
  return true
}

const spawnScript = (
  command: string,
  options: RunProcessOptions
): Promise<CommandOutput> => {
  const { args, ...rest } = options
  return spawn("script", {
    args: ["-q", "/dev/null", command, ...(args as string[])],
    ...rest,
  })
}

const testContracts = async (
  repo: Repo
): Promise<{ build: CommandOutput; test?: CommandOutput }> => {
  const contractsPath = getRepoContractsPath(repo)
  await ensurePathExists(contractsPath)
  // Check if it builds
  const build = await spawnScript(sforgeBinary, {
    args: ["build", "--color", "always"],
    cwd: contractsPath,
    stdio: ["inherit", "pipe", "pipe"],
  })
  if (build.exitCode !== 0) {
    return { build }
  }
  // Check if the tests pass
  const test = await spawnScript(sforgeBinary, {
    args: ["test", "--color", "always"],
    cwd: contractsPath,
    stdio: ["inherit", "pipe", "pipe"],
  })
  return { build, test }
}

const runRepo = async (
  repo: Repo
): Promise<{ build: CommandOutput; test?: CommandOutput } | null> => {
  const repoExists = await ensureRepoExists(repo)
  if (repoExists) {
    return await testContracts(repo)
  } else {
    console.warn(`Repo ${repo.repo} does not exist. Skipping these tests...`)
    return null
  }
}

const showTestOutput = (output: TestOutput) => {
  const status = output.success ? "✅ Success" : "❌ Error"
  console.log(`\n--- ${output.repo} ${status} ---`)
  if (output.success) {
    return
  }

  if (output.build) {
    if (output.build.stdout.length > 0) {
      console.log("\nBuild stdout:")
      process.stdout.write(output.build.stdout)
      console.log("")
    }
    if (output.build.stderr.length > 0) {
      console.log("\nBuild stderr:")
      process.stderr.write(output.build.stderr)
      console.log("")
    }
  }
  if (output.test) {
    if (output.test.stdout.length > 0) {
      console.log("\nTest stdout:")
      process.stdout.write(output.test.stdout)
      console.log("")
    }
    if (output.test.stderr.length > 0) {
      console.log("\nTest stderr:")
      process.stderr.write(output.test.stderr)
      console.log("")
    }
  }
}

beforeAll(() => {
  Error.stackTraceLimit = 0
})
describe("sforge tests", async () => {
  const allOutputs: TestOutput[] = []

  // Run each repo as a separate test and collect outputs
  for (const repo of repos) {
    test(
      `repo: ${repo.repo || repo}`,
      async () => {
        const errors: string[] = []
        try {
          const process = await runRepo(repo)
          if (process) {
            // Collect outputs for later logging
            const buildSuccess = process.build?.exitCode === 0
            const testSuccess = process.test?.exitCode === 0
            const outputs = {
              repo: repo.repo,
              success: buildSuccess && testSuccess,
              build: process.build,
              test: process.test,
            }
            allOutputs.push(outputs)
            if (!buildSuccess) {
              errors.push("sforge build failed")
            } else if (!testSuccess) {
              errors.push("sforge test failed")
            }
            // Add more specific assertions as needed
          } else {
            const outputs = {
              repo: repo.repo,
              success: false,
              error: "runRepo returned null/undefined",
            }
            allOutputs.push(outputs)
            errors.push("repo not found locally")
          }
        } catch (error) {
          // Capture errors but still collect for logging
          const errorMsg =
            error instanceof Error ? error.message : String(error)
          allOutputs.push({
            repo: repo.repo,
            success: false,
            error: errorMsg,
          })
          errors.push(errorMsg)
          throw error; // Re-throw to fail the test
        }
        if (errors.length > 0) {
          throw new Error(`${repo.repo}: ${errors.join("\n")}`)
        }
      },
      { timeout: 20_000 }
    )
  }

  // After all tests, log all outputs in order
  afterAll(() => {
    const failedOutputs = allOutputs.filter((output) => !output.success)
    if (failedOutputs.length > 0) {
      console.log("\n=== Failed Outputs ===")
      failedOutputs.forEach(showTestOutput)
    }
  })
})
