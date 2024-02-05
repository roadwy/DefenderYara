
rule PWS_BAT_Lokibot_GG_MTB{
	meta:
		description = "PWS:BAT/Lokibot.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0c 00 00 01 00 "
		
	strings :
		$a_80_0 = {46 75 63 6b 61 76 2e 72 75 } //Fuckav.ru  01 00 
		$a_80_1 = {2a 53 69 74 65 73 2e 64 61 74 } //*Sites.dat  01 00 
		$a_80_2 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //PK11SDR_Decrypt  01 00 
		$a_80_3 = {50 4b 31 31 5f 43 68 65 63 6b 55 73 65 72 50 61 73 73 77 6f 72 64 } //PK11_CheckUserPassword  01 00 
		$a_80_4 = {53 45 4c 45 43 54 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 2c 20 66 6f 72 6d 53 75 62 6d 69 74 55 52 4c 2c 20 68 6f 73 74 6e 61 6d 65 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins  01 00 
		$a_80_5 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //encryptedPassword  01 00 
		$a_80_6 = {73 69 67 6e 6f 6e 73 2e } //signons.  01 00 
		$a_80_7 = {66 69 6c 65 3a 2f 2f 2f } //file:///  01 00 
		$a_80_8 = {6b 65 79 63 68 61 69 6e 2e 70 6c 69 73 74 } //keychain.plist  01 00 
		$a_80_9 = {50 6f 70 50 61 73 73 77 6f 72 64 } //PopPassword  01 00 
		$a_80_10 = {53 6d 74 70 50 61 73 73 77 6f 72 64 } //SmtpPassword  01 00 
		$a_80_11 = {4d 41 43 3d 25 30 32 58 25 30 32 58 25 30 32 58 49 4e 53 54 41 4c 4c 3d 25 30 38 58 25 30 38 58 6b } //MAC=%02X%02X%02XINSTALL=%08X%08Xk  00 00 
	condition:
		any of ($a_*)
 
}