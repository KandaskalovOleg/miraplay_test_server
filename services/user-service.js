const UserModel = require('../models/user-model');
const bcrypt = require('bcrypt');
const uuid = require('uuid');
const MailService = require('./mail-service');
const TokenService = require('./token-service');
const UserDto = require('../dtos/user-dto');
const ApiError = require('../exceptions/api-error');
const tokenService = require('./token-service');

class UserService {
  async registration(email, password) {
    const candidate = await UserModel.findOne({email});
    if (candidate) {
      throw ApiError.BadRequest('Користувач з таким email вже існує');
    };
    const hashPassword = await bcrypt.hash(password, 10);
    const activationLink = uuid.v4();

    const user = await UserModel.create({email, password: hashPassword, activationLink});
    await MailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`);

    const userDto = new UserDto(user);
    const tokens = TokenService.generateTokens({...userDto});
    await TokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto,
    };
  }

  async activate(activationLink) {
    const user = await UserModel.findOne({activationLink});
    if (!user) {
      throw ApiError.BadRequest('Некоректне посилання');
    }
    user.isActivated = true;
    await user.save();
  }

  async login(email, password) {
    const user = await UserModel.findOne({email});
    if (!user) {
      throw ApiError.BadRequest('Користувач з таким email не знайдений');
    }
    if (!user.isActivated) {
      throw ApiError.BadRequest('Для входу підтвердіть адресу email');
    }
    const isPassEquals = await bcrypt.compare(password, user.password);
    if(!isPassEquals) {
      throw ApiError.BadRequest('Невірний пароль');
    }
    
    const userDto = new UserDto(user);
    const tokens = TokenService.generateTokens({...userDto});
    await TokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto,
    };
  }

  async logout(refreshToken) {
    const token = await tokenService.removeToken(refreshToken);
    return token;
  }

  async refresh(refreshToken) {
    if (!refreshToken) {
      throw ApiError.UnauthorizedError();
    }
    const userData = tokenService.validateRefreshToken(refreshToken);
    const tokenFromDB = await tokenService.findToken(refreshToken);
    if (!userData || !tokenFromDB) {
      throw ApiError.UnauthorizedError();
    }
    const user = await UserModel.findById(userData.id);
    const userDto = new UserDto(user);
    const tokens = TokenService.generateTokens({...userDto});
    await TokenService.saveToken(userDto.id, tokens.refreshToken);

    return {
      ...tokens,
      user: userDto,
    };
  }
}

module.exports = new UserService();
