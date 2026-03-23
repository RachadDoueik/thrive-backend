import { Injectable } from '@nestjs/common';
import { PrismaClient } from '../../generated/prisma/client';
import UserSummaryDto from './dto/user-summary-dto';

@Injectable()
export class UsersRepository {
    constructor(private readonly prisma: PrismaClient){}

    async userById(id: string) : Promise<UserSummaryDto | null> {
        const user = await this.prisma.user.findUnique({
            where: { id },
            select: {
                id: true,
                fullName: true,
                email: true,
                role: true
            }
        });
        return user;
    }

    async userByEmail(email: string) : Promise<UserSummaryDto | null> {
        const user = await this.prisma.user.findUnique({
            where: { email },
            select: {
                id: true,
                fullName: true,
                email: true,
                role: true
            }
        });
        return user;
    }
}