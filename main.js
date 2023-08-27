import openid from 'openid';
import url from 'url';

export default class SteamOpenID {
	constructor(realm, returnUrl, apiKey) {
		if (!realm || !returnUrl || !apiKey) {
			throw new Error('Missing a parameter.');
		}

		this.realm = realm;
		this.returnUrl = returnUrl;
		this.apiKey = apiKey;
		this.relyingParty = new openid.RelyingParty(returnUrl, realm, true, true, []);
	}

	async getRedirectUrl() {
		return new Promise((resolve, reject) => {
			this.relyingParty.authenticate('https://steamcommunity.com/openid', false, (error, authUrl) => {
				if (error) return reject(`Authentication failed: ${error}`);
				if (!authUrl) return reject('Authentication failed.');
				resolve(authUrl);
			});
		});
	}

	async fetchIdentifier(steamOpenId) {
		return new Promise(async (resolve, reject) => {
			const steamId = steamOpenId.replace('https://steamcommunity.com/openid/id/', '');

			try {
				const response = await fetch(`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=${this.apiKey}&steamids=${steamId}`);
				const data = await response.json();
				const players = data.response && data.response.players;

				if (players && players.length > 0) {
					resolve(players[0]);
				} else {
					reject('No players found for the given SteamID.');
				}
			} catch (err) {
				reject(`Steam server error: ${err.message}`);
			}
		});
	}

	async authenticate(requestUrl) {
		return new Promise((resolve, reject) => {
			this.relyingParty.verifyAssertion(requestUrl, async (err, res) => {
				if (err) {
					return reject(err.message);
				}
				if (!res || !res.authenticated) {
					return reject('Failed to authenticate user.');
				}
				if (!/^https?:\/\/steamcommunity\.com\/openid\/id\/\d+$/.test(res.claimedIdentifier)) {
					return reject('Claimed identity is not valid.');
				}

				try {
					const OPENID_CHECK = {
						ns: 'http://specs.openid.net/auth/2.0',
						claimed_id: 'https://steamcommunity.com/openid/id/',
						identity: 'https://steamcommunity.com/openid/id/',
					};

					const searchParams = url.parse(requestUrl, true).query;

					if (searchParams['openid.ns'] !== OPENID_CHECK.ns || !searchParams['openid.claimed_id']?.startsWith(OPENID_CHECK.claimed_id) || !searchParams['openid.identity']?.startsWith(OPENID_CHECK.identity) || searchParams['openid.op_endpoint'] !== 'https://steamcommunity.com/openid/login') {
						return reject('Claimed identity is not valid.');
					}

					const user = await this.fetchIdentifier(res.claimedIdentifier);
					return resolve(user);
				} catch (err) {
					reject(err);
				}
			});
		});
	}
}