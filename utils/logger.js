const setupLogger = () => {
  return {
    info: (message, meta = {}) => {
      console.log(`[INFO] ${message}`, meta);
    },
    error: (message, error = null) => {
      console.error(`[ERROR] ${message}`, error);
    },
    warn: (message, meta = {}) => {
      console.warn(`[WARN] ${message}`, meta);
    },
    debug: (message, meta = {}) => {
      console.log(`[DEBUG] ${message}`, meta);
    }
  };
};

module.exports = { setupLogger }; 