import { User } from "../entities/user.entity";

export interface LonginResponse {
    user: User;
    token: string;
}