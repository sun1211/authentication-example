// database.config.ts
import { DataSource } from 'typeorm';
import { dataSource } from './orm.config';

export const getDBConnection = async (): Promise<DataSource> => {
  try {
    if (dataSource.isInitialized) return dataSource;
    await dataSource.initialize();

    console.info('Connected to MongoDB successfully');

    return dataSource;
  } catch (err) {
    console.error('MongoDB connection ERROR:', err);
    throw err;
  }
};

// For MongoDB, write and read operations use the same connection
// You can implement replica sets later if needed
export const getWriteConnection = async (): Promise<DataSource> => {
  return getDBConnection();
};

export const getReadConnection = async (): Promise<DataSource> => {
  return getDBConnection();
};