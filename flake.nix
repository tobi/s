{
  description = "Secret Exec (s) — encrypted env store with a 7-day session";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        s = pkgs.rustPlatform.buildRustPackage {
          pname = "s";
          version = "0.4.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # No C libraries needed; argon2/chacha20/sha2/etc. are pure Rust.
          # Only `rpassword` touches the terminal via libc, which is always
          # present. Nothing else to wire up.

          meta = with pkgs.lib; {
            description = "Secret Exec — encrypted env store with a 7-day boot-clock-bound session";
            license = licenses.mit;
            platforms = platforms.linux ++ platforms.darwin;
            mainProgram = "s";
          };
        };
      in
      {
        packages.default = s;
        packages.s = s;

        apps.default = {
          type = "app";
          program = "${s}/bin/s";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [ cargo rustc rustfmt clippy ];
        };
      });
}
