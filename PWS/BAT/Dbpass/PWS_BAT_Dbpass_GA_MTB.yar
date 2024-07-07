
rule PWS_BAT_Dbpass_GA_MTB{
	meta:
		description = "PWS:BAT/Dbpass.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 0e 00 00 "
		
	strings :
		$a_80_0 = {3c 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 3e } //<encryptedPassword>  1
		$a_80_1 = {3c 55 72 6c 3e } //<Url>  1
		$a_80_2 = {3c 6c 6f 67 69 6e 73 3e } //<logins>  1
		$a_80_3 = {3c 43 6f 75 6e 74 72 79 3e } //<Country>  1
		$a_80_4 = {54 65 6c 65 67 72 61 6d 2e 42 6f 74 } //Telegram.Bot  1
		$a_80_5 = {5c 50 61 73 73 77 6f 72 64 } //\Password  1
		$a_80_6 = {5c 63 6f 6f 6b 69 65 73 } //\cookies  1
		$a_80_7 = {5c 41 75 74 6f 66 69 6c 6c } //\Autofill  1
		$a_80_8 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //checkip.dyndns.org  1
		$a_80_9 = {69 70 69 6e 66 6f 2e 69 6f } //ipinfo.io  1
		$a_80_10 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //PK11SDR_Decrypt  1
		$a_80_11 = {70 61 79 6d 65 6e 74 41 63 63 6f 75 6e 74 49 44 } //paymentAccountID  1
		$a_80_12 = {53 45 4c 45 43 54 20 61 63 74 69 6f 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 20 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //SELECT action_url, username_value , password_value FROM logins  1
		$a_80_13 = {53 45 4c 45 43 54 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 2c 20 68 6f 73 74 6e 61 6d 65 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=10
 
}