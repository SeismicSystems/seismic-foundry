import type { Hex } from "viem";
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

const chain = sanvil;
const { url, exitProcess } = await setupNode(chain);
const account = privateKeyToAccount(privateKey);

const pcParams = { chain, url };

const encryptionSk = generatePrivateKey();
const encryptionPubkey = privateKeyToAccount(encryptionSk).publicKey;

beforeAll(async () => {
  await buildNode(chain)
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
