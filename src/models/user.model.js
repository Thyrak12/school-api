export default (sequelize, DataTypes) =>
    sequelize.define('Users', {
        email: DataTypes.STRING,
        name: DataTypes.STRING,
        password: DataTypes.STRING
    });
