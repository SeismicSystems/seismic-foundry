export type Repo = {
  repo: string;
  remote: string;
  contracts?: string;
};

export const repos: Repo[] = [
  // {
  //   repo: "forge-std",
  //   remote: "git@github.com:foundry-rs/forge-std.git",
  // },
  // {
  //   repo: "poker",
  //   remote: "git@github.com:SeismicSystems/poker.git",
  //   contracts: "contracts",
  // },
  {
    repo: "moonhatch",
    remote: "git@github.com:SeismicSystems/moonhatch.git",
    contracts: "contracts",
  },
];
