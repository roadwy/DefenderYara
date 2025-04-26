
rule PWS_BAT_Stealer_MAK_MTB{
	meta:
		description = "PWS:BAT/Stealer.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 14 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //get_Password  1
		$a_80_1 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } //set_Password  1
		$a_80_2 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //get_encryptedPassword  1
		$a_80_3 = {73 65 74 5f 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //set_encryptedPassword  1
		$a_80_4 = {67 65 74 5f 55 73 65 72 6e 61 6d 65 } //get_Username  1
		$a_80_5 = {73 65 74 5f 55 73 65 72 6e 61 6d 65 } //set_Username  1
		$a_80_6 = {67 65 74 5f 6c 6f 67 69 6e 73 } //get_logins  1
		$a_80_7 = {73 65 74 5f 6c 6f 67 69 6e 73 } //set_logins  1
		$a_80_8 = {67 65 74 5f 57 65 62 48 6f 6f 6b } //get_WebHook  1
		$a_80_9 = {73 65 74 5f 57 65 62 48 6f 6f 6b } //set_WebHook  1
		$a_80_10 = {50 61 73 73 52 65 61 64 65 72 } //PassReader  1
		$a_80_11 = {52 65 61 64 50 61 73 73 77 6f 72 64 73 } //ReadPasswords  1
		$a_80_12 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntiVirusProduct  1
		$a_80_13 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //select * from Win32_OperatingSystem  1
		$a_80_14 = {53 74 65 61 6c 65 72 } //Stealer  1
		$a_80_15 = {56 69 63 74 69 6d 20 54 69 6d 65 3a } //Victim Time:  1
		$a_80_16 = {41 6e 74 69 76 69 72 75 73 3a } //Antivirus:  1
		$a_80_17 = {4c 6f 63 61 6c 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //Local\Google\Chrome\User Data\Default\Login Data  1
		$a_80_18 = {53 45 4c 45 43 54 20 61 63 74 69 6f 6e 5f 75 72 6c 2c 20 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c 20 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 20 46 52 4f 4d 20 6c 6f 67 69 6e 73 } //SELECT action_url, username_value, password_value FROM logins  1
		$a_80_19 = {53 45 4c 45 43 54 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 2c 20 68 6f 73 74 6e 61 6d 65 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //SELECT encryptedUsername, encryptedPassword, hostname FROM moz_logins  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1) >=20
 
}