export type JwtPayload = Record<string, unknown>;

/** The shape every verification failure rejects with. */
export interface ClientErrorRejection {
  clientError: {
    message: string;
    code: string;
  };
}

export function clientErrorRejection(message: string, code: string): Promise<never> {
  const rejection: ClientErrorRejection = { clientError: { message, code } };
  return Promise.reject(rejection);
}

export function isClientErrorRejection(e: unknown): e is ClientErrorRejection {
  return (
    typeof e === "object" &&
    e !== null &&
    typeof (e as ClientErrorRejection).clientError?.message === "string"
  );
}
