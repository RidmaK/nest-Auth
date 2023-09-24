import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinTable,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  Long,
} from 'typeorm';
import { RegisterType, Status } from '../types/user.types';

@Entity({ name: 'users' })
export class User {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: number;

  @Column({ nullable: true })
  username: string;

  @Column({ nullable: true })
  experience: string;

  @Column({ nullable: true, type: 'text' })
  description: string;

  @Column({ nullable: true })
  phone: string;

  @Column({ nullable: true })
  first_name: string;

  @Column({ nullable: true })
  last_name: string;

  @Column({ nullable: true, unique: true })
  email: string;

  @Column({ nullable: true })
  password: string;

  @Column({ nullable: true, unique: true })
  pending_email: string;

  @Column({ default: false })
  is_verified: boolean;

  @Column({ nullable: true })
  verification_code: number;

  @Column({ nullable: true })
  otp_code: number;

  @Column({ type: 'enum', enum: RegisterType, default: RegisterType.MANUAL })
  register_type: RegisterType;

  @Column({ type: 'enum', enum: Status, default: Status.PENDING })
  status: Status;

  @Column({ nullable: true })
  google_access_token: string;

  @CreateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
  })
  created_at: Date;

  @UpdateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP(6)',
    onUpdate: 'CURRENT_TIMESTAMP(6)',
  })
  updated_at: Date;
  length: number;
}
