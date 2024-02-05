
rule Trojan_Win32_Wilbot_AS_MTB{
	meta:
		description = "Trojan:Win32/Wilbot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {69 6e 74 65 72 65 73 74 5c 77 69 6c 6c 2e 70 64 62 } //interest\will.pdb  03 00 
		$a_80_1 = {46 72 75 69 74 70 69 74 63 68 } //Fruitpitch  03 00 
		$a_80_2 = {47 6f 76 65 72 6e } //Govern  03 00 
		$a_80_3 = {53 6f 6e 73 70 65 6c 6c } //Sonspell  03 00 
		$a_80_4 = {47 65 74 54 65 6d 70 50 61 74 68 57 } //GetTempPathW  03 00 
		$a_80_5 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 45 78 57 } //FindFirstFileExW  03 00 
		$a_80_6 = {47 65 74 55 73 65 72 44 65 66 61 75 6c 74 4c 6f 63 61 6c 65 4e 61 6d 65 } //GetUserDefaultLocaleName  00 00 
	condition:
		any of ($a_*)
 
}