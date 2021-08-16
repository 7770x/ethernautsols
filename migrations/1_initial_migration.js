const Migrations = artifacts.require("Token");

module.exports = function (deployer) {
  deployer.deploy(Migrations, 21000000);
};

