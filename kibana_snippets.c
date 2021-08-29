
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

  async init() {
    if (this.compiler) {
      return this;
    }

    const compilerConfig = this.getConfig();
    this.compiler = webpack(compilerConfig);

    // register the webpack compiler hooks
    // for the base optimizer
    this.registerCompilerHooks();

    return this;
  }

  registerCompilerHooks() {
    this.registerCompilerDoneHook();
  }

  registerCompilerDoneHook() {
    this.compiler.hooks.done.tap('base_optimizer-done', stats => {
      // We are not done while we have an additional
      // compilation pass to run
      // We also don't need to emit the stats if we don't have
      // the profile option set
      if (!this.profile || stats.compilation.needAdditionalPass) {
        return;
      }

      const path = this.uiBundles.resolvePath('stats.json');
      const content = JSON.stringify(stats.toJson());
      writeFile(path, content, function (err) {
        if (err) throw err;
      });
    });
  }


  constructor(private readonly coreContext: CoreContext) {
    const { logger, configService, env } = coreContext;

    this.logger = logger;
    this.env = env;
    this.log = logger.get('http');
    this.config$ = combineLatest([
      configService.atPath<HttpConfigType>(httpConfig.path),
      configService.atPath<CspConfigType>(cspConfig.path),
      configService.atPath<ExternalUrlConfigType>(externalUrlConfig.path),
    ]).pipe(map(([http, csp, externalUrl]) => new HttpConfig(http, csp, externalUrl)));
    const shutdownTimeout$ = this.config$.pipe(map(({ shutdownTimeout }) => shutdownTimeout));
    this.httpServer = new HttpServer(logger, 'Kibana', shutdownTimeout$);
    this.httpsRedirectServer = new HttpsRedirectServer(logger.get('http', 'redirect', 'server'));
  }
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
  constructor(private readonly coreContext: CoreContext) {
    const { logger, configService, env } = coreContext;

    this.logger = logger;
    this.env = env;
    this.log = logger.get('http');
    this.config$ = combineLatest([
      configService.atPath<HttpConfigType>(httpConfig.path),
      configService.atPath<CspConfigType>(cspConfig.path),
      configService.atPath<ExternalUrlConfigType>(externalUrlConfig.path),
    ]).pipe(map(([http, csp, externalUrl]) => new HttpConfig(http, csp, externalUrl)));
    const shutdownTimeout$ = this.config$.pipe(map(({ shutdownTimeout }) => shutdownTimeout));
    this.httpServer = new HttpServer(logger, 'Kibana', shutdownTimeout$);
    this.httpsRedirectServer = new HttpsRedirectServer(logger.get('http', 'redirect', 'server'));
  }
 constructor(private readonly coreContext: CoreContext) {
    const { logger, configService, env } = coreContext;

    this.logger = logger;
    this.env = env;
    this.log = logger.get('http');
    this.config$ = combineLatest([
      configService.atPath<HttpConfigType>(httpConfig.path),
      configService.atPath<CspConfigType>(cspConfig.path),
      configService.atPath<ExternalUrlConfigType>(externalUrlConfig.path),
    ]).pipe(map(([http, csp, externalUrl]) => new HttpConfig(http, csp, externalUrl)));
    const shutdownTimeout$ = this.config$.pipe(map(({ shutdownTimeout }) => shutdownTimeout));
    this.httpServer = new HttpServer(logger, 'Kibana', shutdownTimeout$);
    this.httpsRedirectServer = new HttpsRedirectServer(logger.get('http', 'redirect', 'server'));
  }



