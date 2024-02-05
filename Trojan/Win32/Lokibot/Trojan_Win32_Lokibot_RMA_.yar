
rule Trojan_Win32_Lokibot_RMA_{
	meta:
		description = "Trojan:Win32/Lokibot.RMA!!Lokibot.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {66 69 6c 65 3a 2f 2f 2f } //file:///  01 00 
		$a_80_1 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //PK11SDR_Decrypt  01 00 
		$a_80_2 = {48 54 54 50 20 50 61 73 73 77 6f 72 64 } //HTTP Password  01 00 
		$a_80_3 = {70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 } //password_value  01 00 
		$a_80_4 = {75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 } //username_value  01 00 
		$a_80_5 = {53 45 4c 45 43 54 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 2c 20 66 6f 72 6d 53 75 62 6d 69 74 55 52 4c 2c 20 68 6f 73 74 6e 61 6d 65 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins  01 00 
		$a_80_6 = {46 75 63 6b 61 76 2e 72 75 } //Fuckav.ru  00 00 
	condition:
		any of ($a_*)
 
}