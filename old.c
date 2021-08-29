export default class BaseOptimizer {
  constructor(opts) {
    this.logWithMetadata = opts.logWithMetadata || (() => null);
    this.uiBundles = opts.uiBundles;
    this.profile = opts.profile || false;

    switch (opts.sourceMaps) {
      case true:
        this.sourceMaps = 'source-map';
        break;

      case 'fast':
        this.sourceMaps = 'cheap-module-eval-source-map';
        break;

      default:
        this.sourceMaps = opts.sourceMaps || false;
        break;
    }

    // Run some pre loading in order to prevent
    // high delay when booting thread loader workers
    this.warmupThreadLoaderPool();
  }
export default class BaseOptimizer {
  constructor(opts) {
    this.logWithMetadata = opts.logWithMetadata || (() => null);
    this.uiBundles = opts.uiBundles;
    this.profile = opts.profile || false;

    switch (opts.sourceMaps) {
      case true:
        this.sourceMaps = 'source-map';
        break;

      case 'fast':
        this.sourceMaps = 'cheap-module-eval-source-map';
        break;

      default:
        this.sourceMaps = opts.sourceMaps || false;
        break;
    }

    // Run some pre loading in order to prevent
    // high delay when booting thread loader workers
    this.warmupThreadLoaderPool();
  }
