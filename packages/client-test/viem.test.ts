import type { Chain, Hex } from "viem"
import { sanvil } from "seismic-viem"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { beforeAll, afterAll, describe, test } from "bun:test"
import {
  setupNode,
  testAesKeygen,
  testAesGcm,
  testEcdh,
  testHkdfHex,
  testHkdfString,
  testRng,
  testRngWithPers,
  testSecp256k1,
  testSeismicCallTypedData,
  testSeismicTx,
  testSeismicTxEncoding,
  testSeismicTxTypedData,
  testWsConnection,
  buildNode,
} from "seismic-viem-tests"

const TIMEOUT_MS = 10_000

const privateKey = process.env.PRIVATE_KEY as Hex
if (!privateKey) {
  throw new Error("PRIVATE_KEY is not set")
}
const account = privateKeyToAccount(privateKey)
const encryptionSk = generatePrivateKey()
const encryptionPubkey = privateKeyToAccount(encryptionSk).publicKey

const chain = sanvil
const port = 8545

let url: string
let wsUrl: string
let exitProcess: () => void
let pcParams: { chain: Chain, url: string }

beforeAll(async () => {
  await buildNode(chain)
  const node = await setupNode(chain, { port, ws: true })
  pcParams = { chain, url: node.url }
  exitProcess = node.exitProcess
  url = node.url
  wsUrl = `ws://localhost:${port}`
})

describe("Seismic Contract", async () => {
  test(
    "deploy & call contracts with seismic tx",
    () => testSeismicTx({ chain, url, account }),
    {
      timeout: TIMEOUT_MS,
    }
  )
})

describe("Seismic Transaction Encoding", async () => {
  test(
    "node detects and parses seismic transaction",
    () =>
      testSeismicTxEncoding({
        chain,
        account,
        url,
        encryptionSk,
        encryptionPubkey,
      }),
    {
      timeout: TIMEOUT_MS,
    }
  )
})

describe("Typed Data", async () => {
  test(
    "client can sign a seismic typed message",
    () =>
      testSeismicCallTypedData({
        chain,
        account,
        url,
        encryptionSk,
        encryptionPubkey,
      }),
    { timeout: TIMEOUT_MS }
  )

  test(
    "client can sign via eth_signTypedData",
    () =>
      testSeismicTxTypedData({
        account,
        chain,
        url,
        encryptionSk,
        encryptionPubkey,
      }),
    { timeout: TIMEOUT_MS }
  )
})

describe("AES", async () => {
  test("generates AES key correctly", testAesKeygen)
})

describe("Websocket Connection", () => {
  test(
    "should connect to the ws",
    async () => {
      await testWsConnection({
        chain,
        wsUrl,
      })
    },
    { timeout: TIMEOUT_MS }
  )
})

describe("Seismic Precompiles", async () => {
  test("RNG(1)", () => testRng({ chain, url }, 1), { timeout: TIMEOUT_MS })
  test("RNG(8)", () => testRng({ chain, url }, 8), { timeout: TIMEOUT_MS })
  test("RNG(16)", () => testRng({ chain, url }, 16), { timeout: TIMEOUT_MS })
  test("RNG(32)", () => testRng({ chain, url }, 32), { timeout: TIMEOUT_MS })
  test("RNG(32, pers)", () => testRngWithPers({ chain, url }, 32), {
    timeout: TIMEOUT_MS,
  })
  test("ECDH", () => testEcdh({ chain, url }), { timeout: TIMEOUT_MS })
  test("HKDF(string)", () => testHkdfString({ chain, url }), {
    timeout: TIMEOUT_MS,
  })
  test("HKDF(hex)", () => testHkdfHex({ chain, url }), { timeout: TIMEOUT_MS })
  test("AES-GCM", () => testAesGcm({ chain, url }), { timeout: TIMEOUT_MS })
  test("secp256k1", () => testSecp256k1({ chain, url }), {
    timeout: TIMEOUT_MS,
  })
})

afterAll(() => {
  exitProcess()
})
