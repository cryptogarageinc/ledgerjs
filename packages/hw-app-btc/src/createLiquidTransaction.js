// @flow

import type Transport from "@ledgerhq/hw-transport";
import { hashPublicKey } from "./hashPublicKey";
import { getWalletPublicKey } from "./getWalletPublicKey";
import type { AddressFormat } from "./getWalletPublicKey";
import { startUntrustedHashTransactionInput } from "./startUntrustedHashTransactionInput";
import { getTrustedInputBIP143 } from "./getTrustedInputBIP143";
import { compressPublicKey } from "./compressPublicKey";
import { signTransaction } from "./signTransaction";
import { provideOutputFullChangePath } from "./finalizeInput";
import { hashOutputFullLiquid } from "./finalizeInputLiquid";
import { liquidGetCommitments } from "./liquidGetCommitments";
import { liquidProvideIssuanceInformation } from "./liquidProvideIssuanceInformation";
import type { Transaction } from "./types";
import {
  DEFAULT_LOCKTIME,
  DEFAULT_SEQUENCE,
  SIGHASH_ALL,
  OP_DUP,
  OP_HASH160,
  HASH_SIZE,
  OP_EQUALVERIFY,
  OP_CHECKSIG
} from "./constants";

export type { AddressFormat };

const defaultsSignLiquidTransaction = {
  lockTime: DEFAULT_LOCKTIME,
  sigHashType: SIGHASH_ALL,
  additionals: [],
  onDeviceStreaming: _e => {},
  onDeviceSignatureGranted: () => {},
  onDeviceSignatureRequested: () => {}
};

/**
 *
 */
export type CreateLiquidTransactionArg = {
  inputs: Array<
    [Transaction, number, string, string, string, string, ?string, ?number]
  >,
  associatedKeysets: string[],
  changePath?: string,
  outputs: Array<
    [string, string, string, string, string, ?string, ?string, ?string, ?string]
  >,
  lockTime?: number,
  sigHashType?: number,
  additionals: Array<string>,
  onDeviceStreaming?: ({
    progress: number,
    total: number,
    index: number
  }) => void,
  onDeviceSignatureRequested?: () => void,
  onDeviceSignatureGranted?: () => void
};

/**
 *
 */
export type LiquidOutputArg = {
  assetValueCommitments: Buffer,
  nonce: Buffer,
  remoteBlindingKey: Buffer,
  script: Buffer
};

export async function createLiquidTransaction(
  transport: Transport<*>,
  arg: CreateLiquidTransactionArg
) {
  const {
    inputs,
    associatedKeysets,
    changePath,
    outputs,
    lockTime,
    sigHashType,
    additionals,
    onDeviceStreaming,
    onDeviceSignatureGranted,
    onDeviceSignatureRequested
  } = {
    ...defaultsSignLiquidTransaction,
    ...arg
  };

  // loop: 0 or 1 (before and after)
  // i: index of the input being streamed
  // i goes on 0...n, inluding n. in order for the progress value to go to 1
  // we normalize the 2 loops to make a global percentage
  const notify = (loop, i) => {
    const { length } = inputs;
    if (length < 3) return; // there is not enough significant event to worth notifying (aka just use a spinner)
    const index = length * loop + i;
    const total = 2 * length;
    const progress = index / total;
    onDeviceStreaming({ progress, total, index });
  };

  if (!additionals.includes("liquid")) {
    additionals.push("liquid");
  }
  //const bech32 = additionals.includes("bech32");
  // Inputs are provided as arrays of [transaction, output_index, optional redeem script, optional sequence]
  // associatedKeysets are provided as arrays of [path]
  const nullScript = Buffer.alloc(0);
  const nullPrevout = Buffer.alloc(0);
  const defaultVersion = Buffer.alloc(4);
  defaultVersion.writeUInt32LE(2, 0);
  const trustedInputs: Array<*> = [];
  const signatures = [];
  const publicKeys = [];
  const liquidOutputs: Array<LiquidOutputArg> = [];
  let firstRun = true;
  const targetTransaction: Transaction = {
    inputs: [],
    version: defaultVersion,
    liquid: true
  };

  notify(0, 0);

  // first pass on inputs to get trusted inputs
  for (let input of inputs) {

    const trustedInputAdditionals = [...additionals];
    // Add an issuance flag if necessary
    if (input.length >= 12 && typeof input[8] === "string" && typeof input[9] === "string" && typeof input[10] === "string" && typeof input[11] === "string") {    
      trustedInputAdditionals.push("issuance");
    }

    const trustedInput = await getTrustedInputBIP143(
      transport,
      input[1],
      input[0],
      trustedInputAdditionals
    );
    let sequence = Buffer.alloc(4);
    sequence.writeUInt32LE(
      input.length >= 4 && typeof input[3] === "number"
        ? input[3]
        : DEFAULT_SEQUENCE,
      0
    );
    trustedInputs.push({
      trustedInput: true,
      value: Buffer.from(trustedInput, "hex"),
      sequence
    });
  }

  targetTransaction.inputs = inputs.map(input => {
    let sequence = Buffer.alloc(4);
    sequence.writeUInt32LE(
      input.length >= 4 && typeof input[3] === "number"
        ? input[3]
        : DEFAULT_SEQUENCE,
      0
    );
    return {
      script: nullScript,
      prevout: nullPrevout,
      sequence
    };
  });

  // Collect public keys
  const result = [];
  for (let i = 0; i < inputs.length; i++) {
    const r = await getWalletPublicKey(transport, {
      path: associatedKeysets[i]
    });
    notify(0, i + 1);
    result.push(r);
  }
  for (let i = 0; i < result.length; i++) {
    publicKeys.push(compressPublicKey(Buffer.from(result[i].publicKey, "hex")));
  }

  onDeviceSignatureRequested();

  // Do the first run with all inputs
  await startUntrustedHashTransactionInput(
    transport,
    true,
    targetTransaction,
    trustedInputs,
    true,
    false,
    additionals
  );

  if (changePath) {
    await provideOutputFullChangePath(transport, changePath);
  }

  // Build Liquid specific outputs
  // TODO : support use cases where abf and vbf are not provided
  for (let i = 0; i < outputs.length; i++) {
    let currentOutput = {};    
    currentOutput["script"] = Buffer.from(outputs[i][2], "hex");
    // If asset & value commitments are provided, use them as blind outputs
    if ((typeof outputs[i][6] !== "undefined") && (typeof outputs[i][8] !== "undefined")) {
      currentOutput["nonce"] = Buffer.from(outputs[i][4], "hex");
      currentOutput["remoteBlindingKey"] = undefined;
      currentOutput["assetValueCommitments"] = Buffer.concat([
        Buffer.from(outputs[i][6], "hex"), Buffer.from(outputs[i][8], "hex")]);
    }    
    else {
      currentOutput["nonce"] = Buffer.from(outputs[i][4], "hex");
      currentOutput["remoteBlindingKey"] = Buffer.from(outputs[i][3], "hex");    
      // If the script does not start with OP_RETURN, get the commitment.
      if (currentOutput["script"].length > 0 && currentOutput["script"][0] != 0x6a) {
        const assetValueCommitment = await liquidGetCommitments(
          transport,
          Buffer.from(outputs[i][1], "hex"),
          Buffer.from(outputs[i][0], "hex"),
          i,
          Buffer.from(outputs[i][7], "hex"),
          Buffer.from(outputs[i][5], "hex")
        );
        currentOutput["assetValueCommitments"] = assetValueCommitment["commitment"];
      }
      else {
        currentOutput["assetValueCommitments"] = Buffer.concat([Buffer.from([0x01]), Buffer.from(outputs[i][1], "hex").reverse(), Buffer.from([0x01]), Buffer.from(outputs[i][0], "hex")]);
      }
    }
    liquidOutputs.push(currentOutput);
  }

  await hashOutputFullLiquid(transport, liquidOutputs);

  // Provide pre encoded issuance information (headless mode only) or assume the inputs do not encode issuance information
  let issuanceBuffer = Buffer.alloc(0);
  for (let i = 0; i < inputs.length; i++) {
    if (inputs[i].length >= 12 && typeof inputs[i][8] === "string" && typeof inputs[i][9] === "string" && typeof inputs[i][10] === "string" && typeof inputs[i][11] === "string") {
      issuanceBuffer = Buffer.concat([
        issuanceBuffer,
        Buffer.from(inputs[i][8], "hex").reverse(),
        Buffer.from(inputs[i][9], "hex").reverse(),
        Buffer.from(inputs[i][10], "hex"),
        Buffer.from(inputs[i][11], "hex")
      ]);
    }
    else {
      issuanceBuffer = Buffer.concat([
        issuanceBuffer,
        Buffer.from([0x00])]);
    }
  }

  await liquidProvideIssuanceInformation(transport, issuanceBuffer);

  // Do the second run with the individual transaction
  for (let i = 0; i < inputs.length; i++) {

    if ((typeof associatedKeysets[i] === "undefined") || (associatedKeysets[i].length == 0)) {
      signatures.push("");
      continue;  
    }

    const input = inputs[i];
    let script =
      inputs[i].length >= 3 && typeof input[2] === "string"
        ? Buffer.from(input[2], "hex")
        : Buffer.concat([
            Buffer.from([OP_DUP, OP_HASH160, HASH_SIZE]),
            hashPublicKey(publicKeys[i]),
            Buffer.from([OP_EQUALVERIFY, OP_CHECKSIG])
          ]);
    let pseudoTX = Object.assign({}, targetTransaction);
    let pseudoTrustedInputs = [trustedInputs[i]];
    pseudoTX.inputs = [{ ...pseudoTX.inputs[i], script }];

    if (inputs[i].length >= 9 && typeof input[8] === "string") {
      pseudoTX.inputs[0].nonce = Buffer.from(input[8], "hex").reverse();
    }
    if (inputs[i].length >= 10 && typeof input[9] === "string") {
      pseudoTX.inputs[0].entropy = Buffer.from(input[9], "hex").reverse();
    }
    if (inputs[i].length >= 11 && typeof input[10] === "string") {
      pseudoTX.inputs[0].issuanceAmount = Buffer.from(input[10], "hex");
    }
    if (inputs[i].length >= 12 && typeof input[11] === "string") {
      pseudoTX.inputs[0].inflationKeys = Buffer.from(input[11], "hex");
    }

    await startUntrustedHashTransactionInput(
      transport,
      false,
      pseudoTX,
      pseudoTrustedInputs,
      true,
      false,
      additionals
    );

    if (firstRun) {
      onDeviceSignatureGranted();
      notify(1, 0);
    }

    const signature = await signTransaction(
      transport,
      associatedKeysets[i],
      lockTime,
      sigHashType,
      undefined,
      inputs[i].length >= 8 && typeof input[7] === "string"
        ? Buffer.from(input[7], "hex")
        : undefined,
      additionals
    );
    notify(1, i + 1);

    signatures.push(signature.toString("hex"));
    targetTransaction.inputs[i].script = nullScript;
    if (firstRun) {
      firstRun = false;
    }
  }

  return signatures;
}
