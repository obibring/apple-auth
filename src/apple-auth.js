/**
 * Apple Auth Library that implements the 'Sign in with Apple' in NodeJS.
 * Official Documentation: https://developer.apple.com/sign-in-with-apple/
 * @author: Ananay Arora <i@ananayarora.com>
 */

const axios = require("axios");
const AppleClientSecret = require("./token");
const crypto = require("crypto");
const qs = require("querystring");

class AppleAuth {
  /**
   * Configure the parameters of the Apple Auth class
   * @param {object} config - Configuration options
   * @param {string} config.client_id – Client ID (also known as the Services ID
   *  in Apple's Developer Portal). Example: com.ananayarora.app
   * @param {string} config.team_id – Team ID for the Apple Developer Account
   *  found on top right corner of the developers page
   * @param {string} config.key_id – The identifier for the private key on the Apple
   *  Developer Account page
   * @param {string} privateKeyLocation - Private Key Location / the key itself
   * @param {string} privateKeyMethod - Private Key Method (can be either 'file' or 'text')
   */

  constructor(config, privateKey, privateKeyMethod) {
    if (typeof config == "object") {
      if (Buffer.isBuffer(config)) {
        this._config = JSON.parse(config.toString());
      } else {
        this._config = config;
      }
    } else {
      this._config = JSON.parse(config);
    }
    this._tokenGenerator = new AppleClientSecret(
      this._config,
      privateKey,
      privateKeyMethod
    );
  }

  /**
   * Get the access token from the server
   * based on the grant code
   * @param {string} code
   * @returns {Promise<object>} Access Token object
   */

  accessToken(code) {
    return new Promise((resolve, reject) => {
      this._tokenGenerator
        .generate()
        .then(token => {
          const payload = {
            grant_type: "authorization_code",
            code,
            client_id: this._config.client_id,
            client_secret: token,
          };
          axios({
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            data: qs.stringify(payload),
            url: "https://appleid.apple.com/auth/token",
          })
            .then(response => {
              resolve(response.data);
            })
            .catch(response => {
              reject(
                "AppleAuth Error - An error occurred while getting response from Apple's servers: " +
                  response
              );
            });
        })
        .catch(err => {
          reject(err);
        });
    });
  }

  /**
   * Get the access token from the server
   * based on the refresh token
   * @param {string} refreshToken
   * @returns {object} Access Token object
   */

  refreshToken(refreshToken) {
    return new Promise((resolve, reject) => {
      this._tokenGenerator
        .generate()
        .then(token => {
          const payload = {
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: this._config.client_id,
            client_secret: token,
          };
          axios({
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            data: qs.stringify(payload),
            url: "https://appleid.apple.com/auth/token",
          })
            .then(response => {
              resolve(response.data);
            })
            .catch(err => {
              reject(
                "AppleAuth Error - An error occurred while getting response from Apple's servers: " +
                  err
              );
            });
        })
        .catch(err => {
          reject(err);
        });
    });
  }
}

module.exports = AppleAuth;
