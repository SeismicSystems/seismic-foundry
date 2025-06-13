import { beforeAll, afterAll, describe, test } from "bun:test"
import { runProcess, waitForProcessExit, type RunProcessOptions } from "seismic-viem-tests"
import { repos, type Repo } from "./repos"
import path from "path"
import fs from "fs/promises"
import type { ChildProcess } from "child_process"

let sforgeBinary: string = "sforge"

beforeAll(async () => {
  // build sforge from scratch
})

const getCodeLocation = (): string => new URL("../../..", import.meta.url).pathname
const getRepoLocation = (repo: Repo): string => path.join(getCodeLocation(), repo.repo)
const getRepoContractsPath = (repo: Repo): string => path.join(getRepoLocation(repo), repo.contracts || "")

const ensurePathExists = async (path: string): Promise<void> => {
    const exists = await fs.exists(path)
    if (!exists) {
        throw new Error(`Path ${path} does not exist`)
    }
}

const spawn = async (command: string, options: RunProcessOptions): Promise<ChildProcess> => {
    const process = await runProcess(command, options)
    await waitForProcessExit(process)
    if (process.exitCode !== 0) {
        throw new Error(`Failed to run ${command} with options\n${JSON.stringify(options)}`)
    }
    return process
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
    console.warn(`Repo ${repo.repo} does not exist. Cloning...`)
    await fs.mkdir(repoLocation, { recursive: true })
    
    return false
}

const testContracts = async (repo: Repo): Promise<void> => {
    const contractsPath = getRepoContractsPath(repo)
    await ensurePathExists(contractsPath)
    // Check if it builds
    const build = await spawn(sforgeBinary, {
        args: ["build"],
        cwd: contractsPath,
        stdio: "inherit",
    })
    // Check if the tests pass
    const test = await spawn(sforgeBinary, {
        args: ["test"],
        cwd: contractsPath,
        stdio: "inherit",
    })
}

const runRepo = async (repo: Repo): Promise<void> => {
    await ensureRepoExists(repo)
    await testContracts(repo)
}

describe("sforge tests", () => {
    for (const repo of repos) {
        test(`${repo.repo}`, () => runRepo(repo))
    }
})