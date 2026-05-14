
rule Trojan_Win64_InfoStealer_PAB_MTB{
	meta:
		description = "Trojan:Win64/InfoStealer.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5b 41 32 5d 20 44 6f 6e 65 20 63 6f 6c 6c 65 63 74 69 6e 67 2c } //1 [A2] Done collecting,
		$a_81_1 = {5c 45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //1 \Exodus\exodus.wallet
		$a_81_2 = {5c 43 6f 69 6e 6f 6d 69 5c 43 6f 69 6e 6f 6d 69 5c 77 61 6c 6c 65 74 73 } //1 \Coinomi\Coinomi\wallets
		$a_81_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 } //1 \Microsoft\Edge\User Data
		$a_81_4 = {5c 42 69 74 50 61 79 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //1 \BitPay\Local Storage\leveldb
		$a_81_5 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 } //1 \Google\Chrome\User Data
		$a_81_6 = {57 61 74 65 72 66 6f 78 5c 50 72 6f 66 69 6c 65 73 54 68 75 6e 64 65 72 62 69 72 64 5c 50 72 6f 66 69 6c 65 73 6c 6f 67 69 6e 73 2e 6a 73 6f 6e 6b 65 79 34 2e 64 62 6b 65 79 33 2e 64 62 63 6f 6f 6b 69 65 73 2e 73 71 6c 69 74 65 66 6f 72 6d 68 69 73 74 6f 72 79 2e 73 71 6c 69 74 65 70 6c 61 63 65 73 2e 73 71 6c 69 74 65 } //1 Waterfox\ProfilesThunderbird\Profileslogins.jsonkey4.dbkey3.dbcookies.sqliteformhistory.sqliteplaces.sqlite
		$a_81_7 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //1 SELECT origin_url, username_value, password_value FROM logins
		$a_81_8 = {43 6f 6f 6b 69 65 73 2d 77 61 6c 53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 2c 20 70 61 74 68 2c 20 65 78 70 69 72 65 73 5f 75 74 63 2c 20 69 73 5f 73 65 63 75 72 65 2c 20 69 73 5f 68 74 74 70 6f 6e 6c 79 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 } //1 Cookies-walSELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly FROM cookies
		$a_81_9 = {6f 6e 63 65 5f 6c 6f 63 6b 2e 72 73 } //1 once_lock.rs
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}