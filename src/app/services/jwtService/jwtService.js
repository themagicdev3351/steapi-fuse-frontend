import FuseUtils from '@fuse/utils/FuseUtils';
import axios from 'axios';
import jwtDecode from 'jwt-decode';
/* eslint-disable camelcase */

class JwtService extends FuseUtils.EventEmitter {
  init() {
    this.setInterceptors();
    this.handleAuthentication();
  }

  setInterceptors = () => {
    axios.interceptors.response.use(
      (response) => {
        return response;
      },
      (err) => {
        return new Promise((resolve, reject) => {
          if (err.response.status === 401 && err.config && !err.config.__isRetryRequest) {
            // if you ever get an unauthorized response, logout the user
            this.emit('onAutoLogout', 'Invalid jwt');
            this.setSession(null);
          }
          throw err;
        });
      }
    );
  };

  handleAuthentication = () => {
    const jwt = this.getAccessToken();

    if (!jwt) {
      this.emit('onNoAccessToken');

      return;
    }

    if (this.isAuthTokenValid(jwt)) {
      this.setSession(jwt);
      this.emit('onAutoLogin', true);
    } else {
      this.setSession(null);
      this.emit('onAutoLogout', 'jwt expired');
    }
  };

  createUser = (data) => {
    return new Promise((resolve, reject) => {
      axios.post('/api/auth/local/register', data).then((response) => {
        console.log('response', response)
        if (response.data.user) {
          this.setSession(response.data.jwt);
          resolve(response.data.user);
        } else {
          reject(response.data.error);
        }
      });
    });
  };

  signInWithEmailAndPassword = (email, password) => {
    return new Promise((resolve, reject) => {
      axios
        .post('/api/auth/local', {
          identifier: email,
          password: password,
        })
        .then((response) => {
          if (response.data.user) {
            this.setSession(response.data.jwt);
            resolve(response.data.user);
          } else {
            reject(response.data.error);
          }
        });
    });
  };

  signInWithToken = () => {
    return new Promise((resolve, reject) => {
      axios
        .get('/api/auth/access-token', {
          data: {
            jwt: this.getAccessToken(),
          },
        })
        .then((response) => {
          if (response.data.user) {
            this.setSession(response.data.jwt);
            resolve(response.data.user);
          } else {
            this.logout();
            reject(new Error('Failed to login with token.'));
          }
        })
        .catch((error) => {
          this.logout();
          reject(new Error('Failed to login with token.'));
        });
    });
  };

  updateUserData = (user) => {
    return axios.post('/api/auth/user/update', {
      user,
    });
  };

  setSession = (jwt) => {
    if (jwt) {
      localStorage.setItem('jwt_jwt', jwt);
      axios.defaults.headers.common.Authorization = `Bearer ${jwt}`;
    } else {
      localStorage.removeItem('jwt_jwt');
      delete axios.defaults.headers.common.Authorization;
    }
  };

  logout = () => {
    this.setSession(null);
  };

  isAuthTokenValid = (jwt) => {
    if (!jwt) {
      return false;
    }
    const decoded = jwtDecode(jwt);
    const currentTime = Date.now() / 1000;
    if (decoded.exp < currentTime) {
      console.warn('access token expired');
      return false;
    }

    return true;
  };

  getAccessToken = () => {
    return window.localStorage.getItem('jwt_jwt');
  };
}

const instance = new JwtService();

export default instance;
