import type { Chain, Hex } from "viem";
import {
  sanvil,
} from "seismic-viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { beforeAll, afterAll, describe, test } from "bun:test";
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
} from "seismic-viem-tests";

const privateKey = process.env.PRIVATE_KEY as Hex;
if (!privateKey) {
  throw new Error("PRIVATE_KEY is not set");
}

const account = privateKeyToAccount(privateKey);
const encryptionSk = generatePrivateKey();
const encryptionPubkey = privateKeyToAccount(encryptionSk).publicKey;

const chain = sanvil;
await buildNode(chain)

let exitProcess: () => void;
let pcParams: { chain: Chain, url: string };

beforeAll(async () => {
  await buildNode(chain)
  const node = await setupNode(chain);
  pcParams = { chain, url: node.url };
  exitProcess = node.exitProcess;
})

describe("seismic-viem-tests", () => {
  test("testAes", testAesKeygen);
  test("testAesGcm", () => testAesGcm(pcParams));
  test("testEcdh", () => testEcdh(pcParams));
  test("testHkdfHex", () => testHkdfHex(pcParams));
  test("testHkdfString", () => testHkdfString(pcParams));
  test("testRng", () => testRng(pcParams, 32));
  test("testRngWithPers", () => testRngWithPers(pcParams, 32));
  test("testSecp256k1", () => testSecp256k1(pcParams));
  test("testSeismicCallTypedData", () =>
    testSeismicCallTypedData({
      ...pcParams,
      account,
      encryptionPubkey,
      encryptionSk,
    }));
  test("ws connection", () =>
    testWsConnection({ chain, wsUrl: "ws://localhost:8545" })
  );
  test("testSeismicTx", () => testSeismicTx({ ...pcParams, account }));
  test("testSeismicTxEncoding", () =>
    testSeismicTxEncoding({
      ...pcParams,
      account,
      encryptionPubkey,
      encryptionSk,
    }));
  test("testSeismicTxTypedData", () =>
    testSeismicTxTypedData({
      ...pcParams,
      account,
      encryptionPubkey,
      encryptionSk,
    }));
});

afterAll(() => {
  exitProcess();
});
