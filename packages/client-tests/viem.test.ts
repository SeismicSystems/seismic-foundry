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
  testSeismicTxTrace,
  testLegacyTxTrace,
} from "seismic-viem-tests"

const TIMEOUT_MS = 10_000
const chain = sanvil
const port = 8545

const TEST_ACCOUNT_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
const account = privateKeyToAccount(TEST_ACCOUNT_PRIVATE_KEY)
const encryptionSk = '0x311d54d3bf8359c70827122a44a7b4458733adce3c51c6b59d9acfce85e07505'
const encryptionPubkey = '0x028e76821eb4d77fd30223ca971c49738eb5b5b71eabe93f96b348fdce788ae5a0'


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

describe('Transaction Trace', async () => {
  test(
    'Seismic Tx removes input from trace',
    async () => {
      await testSeismicTxTrace({ chain, url, account })
    },
    {
      timeout: TIMEOUT_MS,
    }
  )
  test(
    'Legacy Tx keeps input in trace',
    async () => {
      await testLegacyTxTrace({ chain, url, account })
    },
    { timeout: TIMEOUT_MS }
  )
})

afterAll(() => {
  exitProcess()
})
