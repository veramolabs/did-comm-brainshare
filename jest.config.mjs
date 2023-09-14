import { defaults } from 'jest-config'

const config = {
  moduleFileExtensions: [...defaults.moduleFileExtensions, 'mts'],
  collectCoverage: false,
  collectCoverageFrom: [
    "src/**/*.ts",
    "!**/types/**",
    "!**/build/**",
    "!**/node_modules/**"
  ],
  coverageReporters: [
    "text",
    "lcov",
    "json"
  ],
  coverageProvider: "v8",
  coverageDirectory: "./coverage",
  testMatch: [
    "**/__tests__/**/*.test.*"
  ],
  automock: false,
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  "transform": {
    "^.+\\.m?tsx?$": [
      "ts-jest",
      {
        "useESM": true,
        "tsconfig": "./tsconfig.json"
      }
    ]
  },
  extensionsToTreatAsEsm: ['.ts'],
  testEnvironment: 'node',
  rootDir: './',
}

export default config