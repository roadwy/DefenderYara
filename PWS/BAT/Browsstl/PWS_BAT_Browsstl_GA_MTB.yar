
rule PWS_BAT_Browsstl_GA_MTB{
	meta:
		description = "PWS:BAT/Browsstl.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 0c 00 00 "
		
	strings :
		$a_80_0 = {54 65 6c 65 67 72 61 6d 2e 42 6f 74 } //Telegram.Bot  1
		$a_80_1 = {54 65 6c 65 67 72 61 6d 42 6f 74 } //TelegramBot  1
		$a_80_2 = {53 74 65 61 6c 65 72 } //Stealer  1
		$a_80_3 = {4c 6f 67 69 6e 73 } //Logins  1
		$a_80_4 = {50 61 73 73 77 6f 72 64 } //Password  1
		$a_80_5 = {43 61 72 64 73 } //Cards  1
		$a_80_6 = {43 6f 6f 6b 69 65 73 } //Cookies  1
		$a_80_7 = {44 61 74 61 20 53 6f 75 72 63 65 3d } //Data Source=  1
		$a_80_8 = {43 61 72 64 4e 75 6d 62 65 72 } //CardNumber  1
		$a_80_9 = {53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 2c 20 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 2c 20 63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //SELECT name_on_card,  expiration_month, expiration_year, card_number_encrypted FROM credit_cards  1
		$a_80_10 = {53 45 4c 45 43 54 20 6f 72 69 67 69 6e 5f 75 72 6c 2c 20 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //SELECT origin_url,  username_value, password_value FROM logins  1
		$a_80_11 = {53 45 4c 45 43 54 20 68 6f 73 74 5f 6b 65 79 2c 20 6e 61 6d 65 2c 20 70 61 74 68 2c 20 69 73 5f 73 65 63 75 72 65 2c 20 65 78 70 69 72 65 73 5f 75 74 63 2c 20 65 6e 63 72 79 70 74 65 64 5f 76 61 6c 75 65 2c 20 69 73 5f 68 74 74 70 6f 6e 6c 79 20 46 52 4f 4d 20 63 6f 6f 6b 69 65 73 } //SELECT host_key, name, path, is_secure, expires_utc, encrypted_value, is_httponly FROM cookies  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=8
 
}