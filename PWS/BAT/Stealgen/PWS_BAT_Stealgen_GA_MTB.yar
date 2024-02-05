
rule PWS_BAT_Stealgen_GA_MTB{
	meta:
		description = "PWS:BAT/Stealgen.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0d 00 00 01 00 "
		
	strings :
		$a_80_0 = {47 72 61 62 62 65 72 } //Grabber  01 00 
		$a_80_1 = {41 6d 65 78 20 43 61 72 64 } //Amex Card  01 00 
		$a_80_2 = {4d 61 73 74 65 72 63 61 72 64 } //Mastercard  01 00 
		$a_80_3 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //PK11SDR_Decrypt  01 00 
		$a_80_4 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c } //\Google\Chrome\User Data\  01 00 
		$a_80_5 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //encryptedPassword  01 00 
		$a_80_6 = {43 6f 6f 6b 69 65 73 } //Cookies  01 00 
		$a_80_7 = {43 72 65 64 69 74 43 61 72 64 73 } //CreditCards  01 00 
		$a_80_8 = {5c 53 63 72 65 65 6e 2e } //\Screen.  01 00 
		$a_80_9 = {53 45 4c 45 43 54 20 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 2c 20 50 72 6f 63 65 73 73 49 44 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 } //SELECT ExecutablePath, ProcessID FROM Win32_Process  01 00 
		$a_80_10 = {45 78 70 6c 6f 69 74 44 69 72 65 63 74 6f 72 79 } //ExploitDirectory  01 00 
		$a_80_11 = {45 78 70 59 65 61 72 } //ExpYear  01 00 
		$a_80_12 = {41 33 31 30 4c 6f 67 67 65 72 } //A310Logger  00 00 
	condition:
		any of ($a_*)
 
}