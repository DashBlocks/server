import js from "@eslint/js";
import globals from "globals";

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.node,
        ...globals.es2021,
        process: "readonly",
      },
    },
    rules: {
      "no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_$",
          varsIgnorePattern: "^_$",
          caughtErrorsIgnorePattern: "^_$",
        },
      ],
      "no-console": "warn",
      "prefer-const": "error",
      "no-var": "error",

      "no-process-exit": "off",
      "handle-callback-err": "error",

      semi: ["error", "always"],
      quotes: ["error", "double"],
      indent: ["error", 2],
      "comma-dangle": ["error", "always-multiline"],
      "arrow-spacing": ["error", { before: true, after: true }],

      "no-eval": "error",
      "no-implied-eval": "error",
    },
  },
  {
    ignores: ["node_modules/", "dist/", "ui/"],
  },
];
