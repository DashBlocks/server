import bcrypt from "bcrypt";
process.stdin.on("data", (data) => {
  const password = data.toString().trim();
  // eslint-disable-next-line no-console
  console.log(bcrypt.hashSync(password, 10));
  process.exit(0);
});