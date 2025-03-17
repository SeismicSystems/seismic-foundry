import { createPublicClient, http, type Hex } from "viem";
import { createShieldedPublicClient, createShieldedWalletClient, sanvil } from "seismic-viem";
import { privateKeyToAccount } from "viem/accounts";
import { beforeAll, afterAll } from "bun:test";
import type { SeismicTransactionRequest } from "seismic-viem";

const privateKey = process.env.PRIVATE_KEY as Hex;

if (!privateKey) {
  throw new Error("PRIVATE_KEY is not set");
}

const account = privateKeyToAccount(privateKey);
const wallet = await createShieldedWalletClient({
  account,
  chain: sanvil,
  transport: http(),
});

const tx: SeismicTransactionRequest = {
  to: "0x0000000000000000000000000000000000000000",
  value: 1n,
  data: "0x",
  gas: 1000000n,
  gasPrice: 1n,
  nonce: 0,
  
};

wallet.sendTransaction({
    
})