import { beforeAll, afterAll, describe, test, expect } from "bun:test"
import { runProcess, waitForProcessExit, type RunProcessOptions } from "seismic-viem-tests"
import { repos, type Repo } from "./repos"
import path from "path"
import fs from "fs/promises"
import type { ChildProcess } from "child_process"

let sforgeBinary: string = "sforge"

beforeAll(async () => {
  // build sforge from scratch
})


type CommandOutput = {
    stdout: string
    stderr: string
    exitCode: number | null
}

type TestOutput = {
    repo: string
    success: boolean
    error?: string
    build?: CommandOutput
    test?: CommandOutput
}

const getCodeLocation = (): string => new URL("../../..", import.meta.url).pathname
const getRepoLocation = (repo: Repo): string => path.join(getCodeLocation(), repo.repo)
const getRepoContractsPath = (repo: Repo): string => path.join(getRepoLocation(repo), repo.contracts || "")

const ensurePathExists = async (path: string): Promise<void> => {
    const exists = await fs.exists(path)
    if (!exists) {
        throw new Error(`Path ${path} does not exist`)
    }
}

const spawn = async (command: string, options: RunProcessOptions): Promise<CommandOutput> => {
    const p = await runProcess(command, {
        ...options,
        env: {
            ...process.env,
            // Force color output for common tools
            FORCE_COLOR: '1',
            COLORTERM: 'truecolor',
            TERM: 'xterm-256color',
            // Tool-specific color flags
            NPM_CONFIG_COLOR: 'always',
            YARN_ENABLE_COLORS: '1',
            // Jest and other test runners
            // CI: "false",
        }
    })
    // Start collecting output immediately
    let stdout = ''
    let stderr = ''
    
    if (p.stdout) {
        p.stdout.on('data', (chunk) => {
            stdout += chunk.toString()
        })
    }

    if (p.stderr) {
        p.stderr.on('data', (chunk) => {
            stderr += chunk.toString()
        })
    }
    
    // Wait for process to complete
    await waitForProcessExit(p)
    
    if (p.exitCode !== 0) {
        throw new Error(`Failed to run ${command} with options\n${JSON.stringify(options)}\nstderr: ${stderr}`)
    }
    
    return {
        stdout,
        stderr,
        exitCode: p.exitCode
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
        console.debug(`Repo ${repo.repo} already exists`)
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

const testContracts = async (repo: Repo): Promise<{ build: CommandOutput, test: CommandOutput }> => {
    const contractsPath = getRepoContractsPath(repo)
    await ensurePathExists(contractsPath)
    // Check if it builds
    const build = await spawn(sforgeBinary, {
        args: ["build"],
        cwd: contractsPath,
        stdio: ["inherit", "pipe", "pipe"],
    })
    // Check if the tests pass
    const test = await spawn(sforgeBinary, {
        args: ["test"],
        cwd: contractsPath,
        stdio: ["inherit", "pipe", "pipe"],
    })
    return { build, test }
}

const runRepo = async (repo: Repo): Promise<{ build: CommandOutput, test: CommandOutput } | null> => {
    const repoExists = await ensureRepoExists(repo)
    if (repoExists) {
        return await testContracts(repo)
    } else {
        console.warn(`Repo ${repo.repo} does not exist. Skipping these tests...`)
        return null
    }
}

describe("sforge tests", async () => {
    const allOutputs: TestOutput[] = []
    
    // Run each repo as a separate test and collect outputs
    for (const repo of repos) {
        test(`repo: ${repo.repo || repo}`, async () => {
            try {
                const process = await runRepo(repo)
                
                if (process) {
                    // Collect outputs for later logging
                    const outputs = {
                        repo: repo.repo,
                        success: true,
                        build: process.build,
                        test: process.test,
                    }
                    allOutputs.push(outputs)
                    
                    // You can still assert on the process results here
                    expect(process).toBeDefined()
                    // Add more specific assertions as needed
                } else {
                    allOutputs.push({
                        repo: repo.repo,
                        success: false,
                        error: 'runRepo returned null/undefined'
                    })
                }
            } catch (error) {
                // Capture errors but still collect for logging
                allOutputs.push({
                    repo: repo.repo,
                    success: false,
                    error: error instanceof Error ? error.message : String(error)
                })
                throw error // Re-throw to fail the test
            }
        })
    }
    
    // After all tests, log all outputs in order
    afterAll(() => {
        console.log('\n=== Collected Outputs ===')
        allOutputs.forEach((output) => {
            console.log(`\n--- ${output.repo} ---`)
            
            if (!output.success) {
                console.log(`❌ Error: ${output.error}`)
                return
            }

            console.log('✅ Success')
            if (output.build?.stdout) {
                console.log(`Build stdout: ${output.build.stdout}`)
            }
            if (output.build?.stderr) {
                console.log(`Build stderr: ${output.build.stderr}`)
            }
            if (output.test?.stdout) {
                console.log(`Test stdout: ${output.test.stdout}`)
            }
            if (output.test?.stderr) {
                console.log(`Test stderr: ${output.test.stderr}`)
            }
        })
    })
})