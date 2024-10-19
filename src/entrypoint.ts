import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import SessionResponseErrorCodes from "./enums/SessionResponseCode";

import { GET as SessionStateGet } from "@/base/lib/hauth/functions/session";
import crypto, { randomInt } from "crypto";
import { redirect } from "next/navigation";
import { serverAuth } from "./serverside/auth";
import prisma from "../prisma";

// Session statesi için buraya ekledim. Burada session detaları alma işlemi yapılacak sadece
const SessionState = async (req: NextRequest, params: ParamsInterface) => {
  switch (req.method ?? "GET") {
    case "GET":
      return await SessionStateGet(req, params);
      break;

    default:
      return await responseNotFound();
      break;
  }
};

// Auth routesi için buraya AuthState verdim login logout işlemleri burada yapılacak.
const AuthState = async (req: NextRequest, params: ParamsInterface) => {
  if (!process.env.HAUTH_DEFAULT_NAMESPACE)
    throw new Error("SET DEFAULT NAMESPACE PLEASE");

  if (params.params.hauth[1] == "authenticate" && req.method == "POST") {
    let body = await req.json();

    let email = body?.email ?? "null";

    var isNamespaceExits =
      req.nextUrl.searchParams.get("namespace")?.toString() ?? undefined;

    var acc = await prisma.admin.findFirst({
      where: {
        email,
        password: body.password ?? "-1",
      },
    });

    if (!acc) {
      return NextResponse.json({
        status: false,
        err: "Account not found.",
      });
    }

    await setToken(
      {
        user: {
          id: acc.id,
          email: acc.email,
          name: acc.name,
        },
      },
      isNamespaceExits
    );
    return NextResponse.json({
      status: true,
      err: acc,
    });
  }
  if (params.params.hauth[1] == "authenticate" && req.method == "DELETE") {
    var namespace: string =
      req.nextUrl.searchParams.get("namespace")?.toString() ??
      process.env.HAUTH_DEFAULT_NAMESPACE;

    const session = await serverAuth(namespace);
    if (session?.payload?.user) {
      cookies().delete("hauth-session-key-" + namespace);
      return NextResponse.json({ status: true }, { status: 200 });
    } else return NextResponse.json({}, { status: 401 });
  }
  return await responseNotFound();
};

// Buraya entrypoint yazdım herşey buradan geçeceği için.
// Burada route handle işlemini yaptım ve sonradan ts tanımlarını yapıp routeleri gerekli fonksiyonlara shutladım.
// Ayrıca eğer route de yanlışlık varsa direkt olarak err 404 response attırdım (Response attırdım :)
export default async function Entrypoint(
  req: NextRequest,
  params: ParamsInterface
) {
  if (!(SessionResponseErrorCodes.SESSION_PARSE_ERROR ?? null))
    throw new Error(
      "please put that variable SESSION_PARSE_ERROR in your env file"
    );

  switch (params.params.hauth[0]) {
    case "session":
      return await SessionState(req, params);
      break;

    case "redirectTo":
      if (!req.nextUrl.searchParams.has("redirectTo"))
        return redirect("/signin");
      return redirect(req.nextUrl.searchParams.get("redirectTo") ?? "/");
      break;

    case "auth":
      return await AuthState(req, params);
      break;

    default:
      return await responseNotFound();
      break;
  }
}

export async function setToken(
  payload: any,
  namespace: string | null | undefined = undefined
) {
  if (
    !(process.env.HAUTH_PRIVATE_ENCODER_AUTH_STRING ?? null) ||
    !process.env.HAUTH_PRIVATE_ENCODER_AUTH_STRING
  )
    throw new Error(
      "please put that variable SESSION_PARSE_ERROR in your env file"
    );

  var JHeaders: AuthBaseHeaderInterface = {
    namespace: namespace ?? "/",
    algorithm: "shit",
    bus: randomInt(1111111, 9999999).toString(),
    // expiresAt 1 günlük token
    expiresAt: (Date.now() + 60 * 60 * 24).toString(),
    issuedAt: Date.now().toString(),
    key: randomInt(1111111, 9999999).toString(),
    master: randomInt(1111111, 9999999).toString(),
    sub: randomInt(1111111, 9999999).toString(),
    type: "shit",
  };

  var JPayload: any = payload;

  var JSignature: AuthBaseSignatureInterface = {
    privateSignature: "",
    publicSignature: "",
  };

  let SHeaders: string = JSON.stringify(JHeaders);
  let SPayload: string = JSON.stringify(JPayload);

  let DHeaders: string = Buffer.from(SHeaders, "utf8").toString("base64url");
  let DPayload: string = Buffer.from(SPayload, "utf8").toString("base64url");

  // Burada signature build yapıyoruz kendimize ait key ile.
  let SPoolString =
    SHeaders + SPayload + process.env.HAUTH_PRIVATE_ENCODER_AUTH_STRING;

  const hash = crypto.createHmac(
    "sha512",
    process.env.HAUTH_PRIVATE_ENCODER_AUTH_STRING
  );

  hash.update(SPoolString);

  let OurDigestHash = hash.digest("hex");

  JSignature.privateSignature = OurDigestHash;
  JSignature.publicSignature = "shit";

  let SSignature: string = JSON.stringify(JSignature);

  let DSignature: string = Buffer.from(SSignature, "utf8").toString(
    "base64url"
  );

  let DToken: string = Buffer.from(
    DHeaders + "." + DPayload + "." + DSignature,
    "utf8"
  ).toString("base64url");

  cookies().set(
    "hauth-session-key-" + namespace ?? process.env.HAUTH_DEFAULT_NAMESPACE,
    DToken
  );
}

export async function checkToken({
  sdata,
  namespace,
}: {
  sdata: string | undefined | null;
  namespace: string | undefined | null;
}): Promise<null | AuthBaseInterface> {
  let sessionData =
    sdata ??
    cookies().get(
      "hauth-session-key-" + namespace ?? process.env.HAUTH_DEFAULT_NAMESPACE
    )?.value ??
    null;
  if (
    (!sessionData || !sessionData || sessionData == "") ??
    !process.env.HAUTH_PRIVATE_ENCODER_AUTH_STRING
  )
    return null;

  // HAUTH_PRIVATE_ENCODER_AUTH_STRING="yarrak1234"
  try {
    // Burada genel base64 lü datayı çözdük
    let ddata = Buffer.from(sessionData, "base64url").toString("utf8");

    // Direk kısayoldan aldım split ederek
    let [headersString, payloadString, signatureString] = ddata.split(".");

    // splitleri base64 decode edelim
    let DHeadersString = Buffer.from(headersString, "base64url").toString(
      "utf8"
    );
    let DPayloadString = Buffer.from(payloadString, "base64url").toString(
      "utf8"
    );
    let DSignatureString = Buffer.from(signatureString, "base64url").toString(
      "utf8"
    );

    // Aldığım verileri json parsa ederek obje olarak aktardım
    let JHeaders: AuthBaseHeaderInterface = JSON.parse(
      DHeadersString
    ) as AuthBaseHeaderInterface;
    let JPayload: any = JSON.parse(DPayloadString) as any;
    let JSignature: AuthBaseSignatureInterface = JSON.parse(
      DSignatureString
    ) as AuthBaseSignatureInterface;

    // Burada signature check yapıyoruz kendimize ait key ile.
    let poolString =
      DHeadersString +
      DPayloadString +
      process.env.HAUTH_PRIVATE_ENCODER_AUTH_STRING;

    const hash = crypto.createHmac(
      "sha512",
      process.env.HAUTH_PRIVATE_ENCODER_AUTH_STRING
    );

    hash.update(poolString);

    let OurDigestHash = hash.digest("hex");

    if (JSignature.privateSignature !== OurDigestHash) return null;
    if (JHeaders.namespace !== namespace) return null;

    return {
      headers: JHeaders,
      payload: JPayload,
      signature: JSignature,
    };
  } catch (err: any) {
    // SESSION Parse Error olarak geri dönüş verdik nedeni ise :)
    console.error(err);
    return null;
  }
}

export async function responseNotFound() {
  return new NextResponse(undefined, { status: 404 });
}
