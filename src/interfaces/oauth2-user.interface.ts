export interface OAuth2User {
    id: string;
    email?: string;
    name?: string;
    given_name?: string;
    family_name?: string;
    preferred_username?: string;
    [key: string]: any;
  }