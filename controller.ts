import express, {
  Request,
  RequestHandler,
  Response,
  NextFunction,
} from "express";
import jwt, { Secret, JwtPayload } from "jsonwebtoken";
import { dev } from "../config";
// import the interface from authorise.ts
import { CustomRequest, TokenInterface } from "./authorise";

//This is the function for creating refresh token:
export const createRefreshToken: RequestHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    //check if there is a cookie (check if user is already logged in)
    if (!req.headers.cookie) {
      return res.status(404).send({
        message: "no cookie found",
      });
    }
    //get token out of the cookie
    const oldToken = req.headers.cookie.split("=")[1];
    if (!oldToken) {
      return res.status(404).send({
        message: "No token found",
      });
    }
    //verify the old token
    const privKey: Secret = dev.app.priv_key;
    jwt.verify(oldToken, String(privKey), function (err, decoded) {
      if (err) {
        console.log(err);
        return res.status(400).send({
          message: "Could not verify token",
        });
      }
      //if the token IS verified --> reset OLD cookies
      req.cookies[`${(decoded as TokenInterface).id}`] = "";
      res.clearCookie(`${(decoded as TokenInterface).id}`);
      //generate the NEW token:
      const payload: JwtPayload = { id: (decoded as TokenInterface).id };
      const newToken = jwt.sign(payload, String(privKey), {
        //expiration needs to be LESS than the old token
        expiresIn: "36s",
      });
      // send the NEW token inside NEW cookie
      res.cookie(String((decoded as TokenInterface).id), newToken, {
        path: "/",
        expires: new Date(Date.now() + 1000 * 34),
        httpOnly: true,
      });
      // set the req id
      (req as CustomRequest).id = (decoded as TokenInterface).id;
      next();
    });
  } catch (error: any) {
    return res.status(500).send({
      message: error.message,
    });
  }
};
