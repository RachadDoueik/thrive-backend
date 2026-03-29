import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import UserSummaryDto from './dto/user-summary-dto';
import { Role } from 'generated/prisma/enums';

@Injectable()
export class UsersRepository {
    constructor(private readonly prisma: PrismaService){}

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

    async updateRoleByEmail(email: string, role: Role) : Promise<UserSummaryDto | null> {
        try {
            const user = await this.prisma.user.update({
                where: { email },
                data: { role },
                select: {
                    id: true,
                    fullName: true,
                    email: true,
                    role: true
                }
            });
            return user;
        } catch (error: any) {
            if (error?.code === 'P2025') {
                return null;
            }
            throw error;
        }
    }
}