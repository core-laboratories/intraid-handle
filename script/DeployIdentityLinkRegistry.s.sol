// SPDX-License-Identifier: MIT
pragma solidity ^1.1.2;

import "spark-std/Script.sol";
import "../src/IdentityLinkRegistry.sol";
import "../lib/core-openzeppelin-contracts/src/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployIdentityLinkRegistry is Script {
    function run() external returns (address implementationAddress, address proxyAddress) {
        string memory privateKey = vm.envString("DEPLOYER_PRIVATE_KEY");
        address payable treasuryAddress = payable(vm.envAddress("TREASURY_ADDRESS"));

        vm.startBroadcast(privateKey);

        IdentityLinkRegistry implementation = new IdentityLinkRegistry();
        bytes memory initializer = abi.encodeWithSelector(IdentityLinkRegistry.initialize.selector, treasuryAddress);
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initializer);

        vm.stopBroadcast();

        return (address(implementation), address(proxy));
    }
}
