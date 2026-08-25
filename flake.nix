{
  description = "Development environment for the Google ZK ERC-4337 portability MVP";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    cre-cli = {
      url = "github:lavalleeale-forks/cre-cli";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      cre-cli,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      nargoArtifacts = {
        x86_64-linux = {
          target = "x86_64-unknown-linux-gnu";
          hash = "sha256-ZASAQL79VamHFYsRE32POPloj2lttNhJEN0bzwRC+4A=";
        };
        aarch64-linux = {
          target = "aarch64-unknown-linux-gnu";
          hash = "sha256-5iuXAXUfL5vRhnFyS2NEr1mNh0XOjN5V1hzCdiI3GBE=";
        };
        aarch64-darwin = {
          target = "aarch64-apple-darwin";
          hash = "sha256-K4qTig6uQR0BBRM+seuXsLHxlCA3svQsn6xyRW9emzI=";
        };
      };

      barretenbergArtifacts = {
        x86_64-linux = {
          target = "amd64-linux";
          hash = "sha256-F6uEdpYXKM3FxptsT/QnyQks7xHR4LAWaSmgQX36fPs=";
        };
        aarch64-linux = {
          target = "arm64-linux";
          hash = "sha256-W9wFUoZUKOpQ2B9Noltao3L0XM4zuqBBnL3c1TK9vzA=";
        };
        aarch64-darwin = {
          target = "arm64-darwin";
          hash = "sha256-VL52Rcg6x2Kjimls/gwUlSI6T5MbgnILyeLkf5pDv4Y=";
        };
      };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          nargoArtifact = nargoArtifacts.${system};
          barretenbergArtifact = barretenbergArtifacts.${system};

          mkBinaryRelease =
            {
              pname,
              version,
              binary,
              url,
              hash,
              description,
              homepage,
            }:
            pkgs.stdenv.mkDerivation {
              inherit pname version;

              src = pkgs.fetchurl { inherit url hash; };
              dontUnpack = true;
              nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
                pkgs.autoPatchelfHook
              ];
              buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
                pkgs.stdenv.cc.cc.lib
              ];

              installPhase = ''
                runHook preInstall
                mkdir -p "$out/bin"
                tar -xzf "$src" -C "$out/bin" ${binary}
                chmod +x "$out/bin/${binary}"
                runHook postInstall
              '';

              meta = {
                inherit description homepage;
                license = pkgs.lib.licenses.mit;
                mainProgram = binary;
                platforms = systems;
                sourceProvenance = [ pkgs.lib.sourceTypes.binaryNativeCode ];
              };
            };

          nargo = mkBinaryRelease {
            pname = "nargo";
            version = "1.0.0-beta.26";
            binary = "nargo";
            url = "https://github.com/noir-lang/noir/releases/download/v1.0.0-beta.26/nargo-${nargoArtifact.target}.tar.gz";
            hash = nargoArtifact.hash;
            description = "Noir compiler and package manager";
            homepage = "https://noir-lang.org/";
          };

          barretenberg = mkBinaryRelease {
            pname = "barretenberg";
            version = "5.2.0";
            binary = "bb";
            url = "https://github.com/AztecProtocol/aztec-packages/releases/download/v5.2.0/barretenberg-${barretenbergArtifact.target}.tar.gz";
            hash = barretenbergArtifact.hash;
            description = "Barretenberg proving backend";
            homepage = "https://github.com/AztecProtocol/aztec-packages";
          };
        in
        {
          inherit nargo barretenberg;
          cre-cli = cre-cli.packages.${system}.default;
        }
      );

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          projectPackages = self.packages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              nodejs_22
              bun
              foundry
              git
              curl
              jq
              cacert
              projectPackages.nargo
              projectPackages.barretenberg
              projectPackages.cre-cli
            ];

            NARGO_BIN = "${projectPackages.nargo}/bin/nargo";
            BB_BIN = "${projectPackages.barretenberg}/bin/bb";
            FOUNDRY_DISABLE_NIGHTLY_WARNING = "1";
          };
        }
      );
    };
}
