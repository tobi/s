{
  description = "s — encrypted env store. your agent doesn't need to know your secrets.";

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
          version = "0.8.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          meta = with pkgs.lib; {
            description = "Encrypted env store — agents use secrets without seeing them";
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
      })
    //
    {
      # Home Manager module (system-independent, must be top-level)
      homeModules.default = { config, lib, pkgs, ... }:
        let
          s = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          cfg = config.programs.s;
        in
        {
          options.programs.s = {
              enable = lib.mkEnableOption "s — encrypted env store";

              package = lib.mkOption {
                type = lib.types.package;
                default = s;
                description = "The s package to use.";
              };

              passwordCommand = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                example = "security find-generic-password -s s-secrets -w";
                description = ''
                  Shell command to retrieve the encryption password.
                  Set as S_KEY="!<command>" in the shell environment.
                  If null, s will prompt on TTY.
                '';
              };
            };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];

            # Set S_KEY in the session environment
            home.sessionVariables = lib.mkIf (cfg.passwordCommand != null) {
              S_KEY = "!${cfg.passwordCommand}";
            };
          };
        };
    };
}
