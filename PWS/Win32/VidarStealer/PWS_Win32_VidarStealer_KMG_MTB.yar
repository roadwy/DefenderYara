
rule PWS_Win32_VidarStealer_KMG_MTB{
	meta:
		description = "PWS:Win32/VidarStealer.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_80_0 = {66 69 6c 65 73 5c 6f 75 74 6c 6f 6f 6b 2e 74 78 74 } //files\outlook.txt  01 00 
		$a_80_1 = {66 69 6c 65 73 5c 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e 74 78 74 } //files\information.txt  01 00 
		$a_80_2 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //passwords.txt  01 00 
		$a_80_3 = {55 73 65 4d 61 73 74 65 72 50 61 73 73 77 6f 72 64 } //UseMasterPassword  01 00 
		$a_80_4 = {5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //\logins.json  01 00 
		$a_80_5 = {73 63 72 65 65 6e 73 68 6f 74 2e 6a 70 67 } //screenshot.jpg  01 00 
		$a_80_6 = {69 6d 61 67 65 2f 6a 70 65 67 } //image/jpeg  01 00 
		$a_80_7 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d 20 } ///c taskkill /im   01 00 
		$a_80_8 = {43 6f 6f 6b 69 65 73 5c 25 73 5f 25 73 2e 74 78 74 } //Cookies\%s_%s.txt  01 00 
		$a_80_9 = {5c 45 6c 65 63 74 72 75 6d 2d 4c 54 43 5c 77 61 6c 6c 65 74 73 } //\Electrum-LTC\wallets  01 00 
		$a_80_10 = {6d 75 6c 74 69 64 6f 67 65 2e 77 61 6c 6c 65 74 } //multidoge.wallet  00 00 
	condition:
		any of ($a_*)
 
}