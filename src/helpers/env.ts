// Example content of env.ts
function env(key: string): string | undefined {
    return process.env[key];
  }
  
  export default env;
  