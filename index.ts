import { sha3_256 as sha3Hash } from "@noble/hashes/sha3";
import { AptosAccount, AptosClient, BCS, TxnBuilderTypes } from "aptos";
import axios from "axios";

const {
  AccountAddress,
  EntryFunction,
  TransactionPayloadEntryFunction,
  RawTransaction,
  ChainId,
  TransactionAuthenticatorEd25519,
  Ed25519PublicKey,
  Ed25519Signature,
  SignedTransaction,
  ModuleId,
  Identifier,
} = TxnBuilderTypes;

const main = async () => {
  const senderAddress =
    "B045D637A12EB24546425726010C5971C2C2E118B286E42795FCDFAC6CB74F35";
  const senderPrivateKey =
    "901A4E7A5AAA4C8CD92FFE5E38359E3E4B3C36AFDDDB34D0639457B5AE67A8C4";

  const recipient =
    "47CA99905206738A27453CE84282A4CAF8619B5D926142126C64E175BA1517B6";

  const amount = 10000000;

  const maxGasUnit = 2000000;
  const gasPrice = 200;

  const timeout = 10;

  const aptosClient = new AptosClient("https://rpc.0l.fyi");

  const privateKey = Buffer.from(senderPrivateKey, "hex");

  const entryFunctionPayload = new TransactionPayloadEntryFunction(
    new EntryFunction(
      ModuleId.fromStr("0x1::ol_account"),
      new Identifier("transfer"),
      [],
      [Buffer.from(recipient, "hex"), BCS.bcsSerializeUint64(amount)]
    )
  );

  const chainId = await aptosClient.getChainId();
  const account = await aptosClient.getAccount(senderAddress);

  const rawTxn = new RawTransaction(
    // Transaction sender account address
    AccountAddress.fromHex(senderAddress),

    BigInt(account.sequence_number),
    entryFunctionPayload,
    // Max gas unit to spend
    BigInt(maxGasUnit),
    // Gas price per unit
    BigInt(gasPrice),
    // Expiration timestamp. Transaction is discarded if it is not executed within 10 seconds from now.
    BigInt(Math.floor(Date.now() / 1_000) + timeout),
    new ChainId(chainId)
  );

  const signer = new AptosAccount(privateKey!);

  const hash = sha3Hash.create();
  hash.update("DIEM::RawTransaction");

  const prefix = hash.digest();
  const body = BCS.bcsToBytes(rawTxn);
  const mergedArray = new Uint8Array(prefix.length + body.length);
  mergedArray.set(prefix);
  mergedArray.set(body, prefix.length);

  const signingMessage = mergedArray;

  const signature = signer.signBuffer(signingMessage);
  const sig = new Ed25519Signature(signature.toUint8Array());

  const authenticator = new TransactionAuthenticatorEd25519(
    new Ed25519PublicKey(signer.pubKey().toUint8Array()),
    sig
  );
  const signedTx = new SignedTransaction(rawTxn, authenticator);

  const bcsTxn = BCS.bcsToBytes(signedTx);

  const res = await axios<{
    hash: string;
  }>({
    method: "POST",
    url: "https://rpc.0l.fyi/v1/transactions",
    headers: {
      "content-type": "application/x.diem.signed_transaction+bcs",
    },
    data: bcsTxn,
  });
  if (res.status === 202) {
    console.log(`https://rpc.0l.fyi/v1/transactions/by_hash/${res.data.hash}`);
  }
};

main();
