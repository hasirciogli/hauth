import { checkToken } from "../entrypoint";

export const serverAuth = async (namespace: string) => {
  let sessionData = checkToken({
    sdata: undefined,
    namespace: namespace,
  });

  if (!sessionData) return null;

  return sessionData;
};
