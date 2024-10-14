import { IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class AuthCredentialsDto {
  @IsString()
  @MinLength(4)
  @MaxLength(20)
  username: string;

  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[\W]).+$/, {
    message:
      'Password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 special character.',
  })
  password: string;
}
