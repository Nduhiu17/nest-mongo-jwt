export default () => ({
  jwt: {
    secret: process.env.JWT_SECRET,
  },
  database: {
    connection_string: process.env.MONGO_URI,
  },
});
