import axios, { AxiosInstance } from "axios";
import { CloudwaysApiError, getEnv, normalizeBaseUrl, optionalEnv } from "./utils.js";

type TokenResponse = {
  access_token?: string;
  token_type?: string;
  expires_in?: number;
};

export class CloudwaysAuth {
  private accessToken?: string;
  private expiresAt = 0;

  constructor(
    private readonly http: AxiosInstance,
    private readonly baseUrl: string,
  ) {}

  async getAccessToken(): Promise<string> {
    const now = Date.now();
    if (this.accessToken && now < this.expiresAt - 60_000) {
      return this.accessToken;
    }

    const email = getEnv("CLOUDWAYS_EMAIL");
    const apiToken = getEnv("CLOUDWAYS_API_TOKEN");
    const preferredPath = optionalEnv("CLOUDWAYS_AUTH_PATH", "/oauth/token")!;

    const response = await this.postToken(preferredPath, email, apiToken).catch(async (error) => {
      if (preferredPath !== "/oauth/access_token" && axios.isAxiosError(error) && error.response?.status === 404) {
        return this.postToken("/oauth/access_token", email, apiToken);
      }
      throw error;
    });

    if (!response.access_token) {
      throw new CloudwaysApiError("Cloudways authentication did not return an access_token");
    }

    this.accessToken = response.access_token;
    this.expiresAt = now + (response.expires_in ?? 3600) * 1000;
    return this.accessToken;
  }

  private async postToken(path: string, email: string, apiToken: string): Promise<TokenResponse> {
    const url = `${normalizeBaseUrl(this.baseUrl)}${path}`;
    const { data } = await this.http.post<TokenResponse>(url, {
      email,
      api_token: apiToken,
    });
    return data;
  }
}

