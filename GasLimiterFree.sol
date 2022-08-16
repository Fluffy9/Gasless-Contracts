pragma solidity ^0.8.7;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface ILSP6 {
    // function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
    // event Executed(uint256 indexed  value, bytes4 selector); 
    // function target() external view returns (address);
    // function getNonce(address address, uint256 channel) external view returns (uint256);
    // function execute(bytes memory calldata) external payable returns (bytes memory);
    function executeRelayCall(bytes memory signature, uint256 nonce, bytes memory _calldata) external payable returns (bytes memory);
}

interface ILSP0  /* is ERC165 */ {
    function owner() external view returns (address);
}
// Gives each user a quota of how much gas*gasprice they can use.
// Every time period (30 days) this is reset
// During the time period, whitelisted bots will execute the user's transaction
// The usage of this execution is measured and subtracted from their quota
// If the usage exceeds this quota, the execution is reverted

//! General implementation notes:
// The quota functions as a hard cap. This should include a slight buffer to improve the UX
// Users should ideally find out that they are reaching their quota cap through the API, not reverting transactions

// Each subscription plan should have it's own contract with a different usage limit depending on the price paid

// Transactions executed on behalf of a user is logged. This will be easy to display with a subgraph

// Whitelisted bots can effectively run a bit wild. 
// Transactions will only succeed if the user has verifiably approved of it and verifiably has enough quota
// In the future, this could be automated through MEV. The database can be made public and bots can call the execute function on them
// At the end of the month, logs can be queried and bots can be refunded and rewarded

contract GasLimiter is ReentrancyGuard {
    address public owner;
    uint256 public constant period = 30 days;
    uint256 public limit;
    mapping(address => Quota) public quota;
    address[] public whitelist;
    string public plan;

    struct Quota {
        uint256 gas;
        uint256 timestamp;
    }
    event Added(address indexed _user, uint _timestamp);
    event Modified(address indexed _user, uint _gas, uint _timestamp);
    event Executed(address indexed _user, address indexed executor, uint256 used, uint256 _nonce);
    event OwnerChanged(address indexed _oldOwner, address indexed newOwner);

    ///`_user` already exists
    /// @param _user the user to add to the plan.
    error UserExists(address _user);
    /// `_used` * `_price` exceeds `_quota`
    /// @param _used the amount of gas used.
    /// @param _price the gas price.
    /// @param _quota the user's quota.
    error GasExceeded(uint256 _used, uint256 _price, uint256 _quota);
    /// `_sender` is not a whitelisted execution runner
    /// @param _sender msg.sender
    error NotWhitelisted(address _sender);
    /// `_sender` is not the owner
    /// @param _sender msg.sender
    error NotOwner(address _sender);

    modifier onlyOwner() {
        if(msg.sender != owner) { revert NotOwner(msg.sender); }
        _;
    }
    modifier onlyWhitelisted() {
        bool isWhitelisted = false;
        for(uint256 i = 0; i < whitelist.length; i++){
            if(msg.sender == whitelist[i]){
                isWhitelisted = true;
                break;
            }
        }
        if(isWhitelisted == false){ revert NotWhitelisted(msg.sender); }
        _;
    }

    // The gas*gasprice limit for this contract, the plan name
    constructor(uint256 _limit, string memory _plan) {
        owner = msg.sender;
        limit = _limit;
        // useless QOL, see the plan name (free, basic, etc) from the contract so we don't forget it 🤪
        plan = _plan;
    }
    // change the owner
    function changeOwner(address _owner) external onlyOwner {
        owner = _owner;
        emit OwnerChanged(msg.sender, _owner);
    }
    // whitelist bots to call the execute function
    function setWhitelist(address[] memory _runners) external onlyOwner {
        whitelist = _runners;
    }
    // change the gas*gasprice limit for this contract
    function setGas(uint256 _limit) external onlyOwner {
        limit = _limit;
    }
    // Add a user to this plan
    function addUser(address _user) internal {
        uint256 now = block.timestamp;
        quota[_user] = Quota(limit, now);
        emit Added(_user, now);
    }
    // Change a user's quota for some special cases I guess
    function setUser(address _user, Quota memory _quota) external onlyOwner {
        quota[_user] = _quota;
        emit Modified(_user, _quota.gas, _quota.timestamp);
    }
    // We're charging on 30 day period subscription
    // Users' don't all start their subscription at the same time, nor do they necessarily make transactions at regular intervals
    // Given the timestamp of the last period recorded and the period length, calculate when the current period started for this user
    function currentPeriodStarted(address _user) public view returns(uint256) {
        uint256 ago = (block.timestamp - quota[_user].timestamp) % period;
        return block.timestamp - ago;
    }
    // QOL function to get the start of the next period
    function nextPeriod(address _user) public view returns(uint256) {
        return currentPeriodStarted(_user) + 30 days;
    }
    // Executes the user's transaction and deducts from their quota
    // Protect the contract from reentrancy as well even though not really necessary
    // If a reset period has elapsed, refill their quota and set a new timestamp for the current period
    // Query the current gas usage before the user's transaction is called.
    // Subtract the gas usage after from the usage before. This is what will be deducted from their quota
    // If the user doesn't have enough quota to cover the usage, revert
    function execute(address _user, bytes memory _signature, uint256 _nonce, bytes memory _calldata) external payable nonReentrant onlyWhitelisted {
        if(quota[_user].timestamp == 0){ addUser(_user); }
        else if(quota[_user].timestamp > block.timestamp + period){
            quota[_user].gas = limit;
            quota[_user].timestamp = currentPeriodStarted(_user);
        }
        address keyManager = ILSP0(_user).owner();
        uint256 initial = gasleft();
        ILSP6(keyManager).executeRelayCall{value: msg.value}(_signature, _nonce, _calldata);
        uint256 remaining = gasleft();
        uint256 used = (initial - remaining)*tx.gasprice;
        if(quota[_user].gas < used) { revert GasExceeded(initial-remaining, tx.gasprice, quota[_user].gas); }
        quota[_user].gas = quota[_user].gas - used;
        emit Executed(_user, msg.sender, used, _nonce);
    }
}
