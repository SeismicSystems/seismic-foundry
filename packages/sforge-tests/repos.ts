export type Repo = {
  repo: string;
  remote: string;
  contracts?: string; // defaults to the root
  clone?: boolean; // if it doesn't exist; defaults to true
};

export const repos: Repo[] = [
  // {
  //   repo: "forge-std",
  //   remote: "git@github.com:foundry-rs/forge-std.git",
  // },
  {
    repo: "moonhatch",
    contracts: "contracts",
    remote: "git@github.com:SeismicSystems/moonhatch.git",
    clone: false,
  },
  {
    repo: "poker",
    contracts: "contracts",
    remote: "git@github.com:SeismicSystems/poker.git",
    clone: false,
  },
];
