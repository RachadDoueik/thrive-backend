import { Injectable } from '@nestjs/common';
import { UsersRepository } from './users.repository';

@Injectable()
export class UsersService {
    constructor(private readonly usersRepository: UsersRepository) {}

    async getUserById(id: string) {
        return this.usersRepository.userById(id);
    }

    async getUserByEmail(email: string) {
        return this.usersRepository.userByEmail(email);
    }

}
