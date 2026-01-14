const { override, fixBabelImports } = require('customize-cra');

// 1. Define a helper function to modify the Webpack config
const ignoreAntdWarnings = (config) => {
  // Ensure the ignoreWarnings array exists (Webpack 5 feature)
  if (!config.ignoreWarnings) {
    config.ignoreWarnings = [];
  }

  // Add a rule to ignore the specific warning from antd
  config.ignoreWarnings.push({
    module: /node_modules\/antd/,
    message: /text-decoration-skip/,
  });

  return config;
};

// 2. Add the helper function to the override pipeline
module.exports = override(
  fixBabelImports('import', {
    libraryName: 'antd',
    libraryDirectory: 'es',
    style: 'css', 
  }),
  ignoreAntdWarnings // <--- Add this line
);