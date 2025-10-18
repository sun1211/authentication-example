// orm.config.ts
import { DataSource } from 'typeorm';

export const dataSource = new DataSource({
  type: 'mongodb',
  host: 'localhost',
  port: 27017,
  username: 'admin',
  password: 'password',
  database: 'myapp',
  authSource: 'admin',
  entities: [
    `${__dirname}/../**/*.entity.{ts,js}`,
  ],
  synchronize: process.env.NODE_ENV === 'development', // Auto-create collections in dev
  logging: process.env.NODE_ENV === 'development',
  // MongoDB connection pool settings
  extra: {
    maxPoolSize: 10,
    minPoolSize: 2,
    maxIdleTimeMS: 60000,
    waitQueueTimeoutMS: 60000,
  },
});