// import "dotenv/config";
// import mysql from "mysql2/promise";

// const connectDB = async () => {
//   const dbConfig = {
//     host: "159.65.157.84",
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     database: process.env.DB_NAME,
//     port: process.env.DB_PORT,
//   };

//   try {
//     const connection = await mysql.createConnection(dbConfig);
//     console.log("DB Connected Successfully !!!");
//     return connection; // Return the connection for use elsewhere
//   } catch (error) {
//     console.error("DB connection Failed !!! : ", error.message);
//     process.exit(1); // Exit process on connection failure
//   }
// };

// export default connectDB;
