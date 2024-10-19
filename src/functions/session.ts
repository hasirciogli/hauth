import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import SessionResponseErrorCodes from "../enums/SessionResponseCode";
import crypto from "crypto";

const GET = async(req: NextRequest, params: ParamsInterface) => {
  let sessionKey =
    cookies().get(
      "hauth-session-key-" + req.nextUrl.searchParams.get("namespace") ??
        process.env.HAUTH_DEFAULT_NAMESPACE
    ) ?? null;
  if (
    !sessionKey ||
    !sessionKey.value ||
    sessionKey.value == "" ||
    !process.env.HAUTH_PRIVATE_ENCODER_AUTH_STRING
  )
    return NextResponse.json({
      status: false,
      err: "Session invalid.",
      errCode: SessionResponseErrorCodes.NOT_FOUND_ON_REQUEST,
    });

  // HAUTH_PRIVATE_ENCODER_AUTH_STRING="yarrak1234"
  try {
    // Burada genel base64 lü datayı çözdük
    let ddata = Buffer.from(sessionKey.value, "base64url").toString("utf8");

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

    if (JSignature.privateSignature !== OurDigestHash)
      return NextResponse.json(
        {
          status: false,
          err: "Session invalid.",
          errCode: SessionResponseErrorCodes.HASH_VALUES_ARE_NOT_EQUALS,
        },
        {
          status: 401,
          statusText: "Session",
        }
      );
    return NextResponse.json(JPayload);
  } catch (err: any) {
    // SESSION Parse Error olarak geri dönüş verdik nedeni ise :)
    console.error(err);
    return NextResponse.json({
      status: false,
      err: "Session invalid.",
      errCode: SessionResponseErrorCodes.SESSION_PARSE_ERROR,
    });
  }
};

export { GET };
