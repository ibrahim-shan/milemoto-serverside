// This file only contains type declarations

declare global {
  namespace Express {
    interface Request {
      id?: string;
      user?: {
        id: string;
        role: 'user' | 'admin';
      };
    }
  }
}

// This file must not have any import/export statements
// so TypeScript treats it as a global augmentation.
export {};
