import express, {
  Request,
  RequestHandler,
  Response,
  NextFunction,
} from "express";
import jwt, { Secret } from "jsonwebtoken";
import { dev } from "../config";

// This is the interface for the token
export interface TokenInterface {
  id: string;
  iat: number;
  exp: number;
}

// This is the interface for the request
export interface CustomRequest extends Request {
  id: string;
}

// This is the middleware function to pass in the routes that need to be authorised
export const isAuthorised: RequestHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    //first check if there is a cookie available
    if (!req.headers.cookie) {
      return res.status(404).send({
        message: "no cookie found",
      });
    }
    //get just the token from the cookie
    const token = req.headers.cookie.split("=")[1];
    if (!token) {
      return res.status(404).send({
        message: "token not found",
      });
    }
    // verify the token
    // the private key is stored in an env variable
    const privKey: Secret = dev.app.priv_key;
    jwt.verify(token, String(privKey), function (err: any, decoded: any) {
      if (err) {
        console.log(err);
        return res.status(400).send({
          message: "Could not verify token",
        });
      }
      //set the req id
      (req as CustomRequest).id = (decoded as TokenInterface).id;
      next();
    });
  } catch (error: any) {
    return res.status(500).send({
      message: error.message,
    });
  }
};
