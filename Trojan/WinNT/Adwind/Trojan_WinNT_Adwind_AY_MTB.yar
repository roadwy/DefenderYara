
rule Trojan_WinNT_Adwind_AY_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.AY!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 72 79 70 74 6f 2f 73 70 65 63 2f 53 65 63 72 65 74 4b 65 79 53 70 65 63 } //01 00 
		$a_00_1 = {49 78 69 79 70 75 7e 60 30 49 72 61 78 76 76 3c } //01 00 
		$a_00_2 = {48 58 48 4b 4b 56 4d 5c 4f 5a 41 41 44 4d 52 } //01 00 
		$a_00_3 = {4a 5d 48 4f 58 4a 41 5b 58 } //01 00 
		$a_00_4 = {36 6b 6e 76 6f 7d 31 68 64 79 3c 76 7b 3d } //01 00 
		$a_00_5 = {5e 38 7a 49 3f 68 65 47 49 35 70 47 30 7c 4c 67 24 7e 26 68 31 } //01 00 
		$a_00_6 = {48 4b 52 4e 5d 4d 5a 47 40 58 40 4b 43 56 45 } //00 00 
	condition:
		any of ($a_*)
 
}