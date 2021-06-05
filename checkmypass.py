import requests
import hashlib
import sys

def request_api_data(querry_char):
	url = 'https://api.pwnedpasswords.com/range/' + querry_char
	res = requests.get(url)
	if res.status_code !=200:
		raise RuntimeError(f'error fetching, {res.status_code}, check api and try again.')
	return res

def password_leak_counts(hashes_received, hash_to_check):
	hashes = (line.split(':') for line in hashes_received.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0

def pwned_check_api(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first_5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first_5_char)
	return password_leak_counts(response, tail)

def main(args):
	for password in args:
		count = pwned_check_api(password)
		if count:
			print(f'{password} was found {count} times... you should probably change your password.')
		else:
			print(f'{password} was NOT found. Carry on!')
	return 'done!'

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:]))

