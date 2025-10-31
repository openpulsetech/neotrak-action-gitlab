const path = require('path');

module.exports = {
  entry: './index.js',
  target: 'node',
  mode: 'production',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'index.js',
    library: {
      type: 'commonjs2'
    }
  },  
  resolve: {
    extensions: ['.js', '.json']
  },
  externals: {
    // Do not bundle certain runtime-only modules. Marking them external
    // avoids webpack trying to resolve Node-specific sub-files (like
    // axios' internal utils) which can fail during bundling.
    axios: 'commonjs axios'
  },
  optimization: {
    minimize: false
  },
  node: {
    __dirname: false,
    __filename: false
  }
};
