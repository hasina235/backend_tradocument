import js from "@eslint/js";
import globals from "globals";
import pluginVue from "eslint-plugin-vue";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs,vue}"],
    plugins: { js },
    extends: ["js/recommended"],
    languageOptions: {
      globals: {
        ...globals.browser, // Pour le code Vue côté front
        ...globals.node     // ✅ Ajoute Node.js (process, __dirname, etc.)
      },
    },
  },
  pluginVue.configs["flat/essential"],
]);
