const { ethers } = require("ethers");
const MyContractArtifact = require("./build/contracts/Token.json");
require("dotenv").config();
const { InfuraProvider } = require("@ethersproject/providers");
const fs = require("fs");
const contract = JSON.parse(fs.readFileSync("./build/contracts/Token.json", "utf8"));

const provider = new InfuraProvider("rinkeby", process.env.INFURA_API_KEY);
var wallet = ethers.Wallet.fromMnemonic(process.env.MNEMONIC);

(async () => {
  try {
    console.log("running...");

    const ABI = contract.abi;

    const readOnlyContract = new ethers.Contract(process.env.CONTRACT_ADDRESS1, ABI, provider);
    const value = await readOnlyContract.totalSupply();
    console.log("totalSupply: ", value.toString());

    // var signer = provider.getSigner();

    wallet = wallet.connect(provider); // Set the provider for the wallet

    const writableContract = new ethers.Contract(process.env.CONTRACT_ADDRESS1, ABI, wallet);
    const transaction = writableContract.transfer(process.env.OUR_ADDRESS1, 10);
    var txResponse = await wallet.sendTransaction(transaction);
    const txReceipt = await txResponse.wait();
    console.log("txReceipt: ", txReceipt);

    // const [eoa, accomplice] = await ethers.getSigners();
    // console.log('eoa, accomplice: ', eoa, accomplice)

    // const eoaAddress = await eoa.getAddress();
    // // contract uses unsigned integer which is always >= 0, overflow check is useless
    // tx = await challenge.connect(accomplice)
    //     // we start with 20 tokens, make sure eoa's balance doesn't overflow as well
    //     .transfer(eoaAddress, BigNumber.from(`2`).pow(256).sub(`21`));
    // await tx.wait();
  } catch (e) {
    console.log(e.message);
  }
})();
