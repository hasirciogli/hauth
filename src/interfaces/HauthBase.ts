interface AuthBaseInterface {
  headers: AuthBaseHeaderInterface;
  payload: any;
  signature: AuthBaseSignatureInterface;
}

interface AuthBaseHeaderInterface {
  namespace: string;
  algorithm: string;
  type: string;
  issuedAt: string;
  expiresAt: string;
  sub: string;
  bus: string;
  master: string;
  key: string;
}

interface AuthBaseSignatureInterface {
  publicSignature: string;
  privateSignature: string;
}
