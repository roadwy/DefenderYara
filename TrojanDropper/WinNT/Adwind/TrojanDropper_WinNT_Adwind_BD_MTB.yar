
rule TrojanDropper_WinNT_Adwind_BD_MTB{
	meta:
		description = "TrojanDropper:WinNT/Adwind.BD!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 68 6d 76 70 78 62 64 79 65 2f 4d 63 76 7a 67 64 75 77 7a 76 7a } //1 bhmvpxbdye/Mcvzgduwzvz
		$a_00_1 = {72 65 73 6f 75 72 63 65 73 2f 6d 6e 76 6e 74 67 73 65 6b 75 } //1 resources/mnvntgseku
		$a_00_2 = {7a 6d 7a 75 6b 72 62 68 65 6b 2e 6a 73 } //1 zmzukrbhek.js
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDropper_WinNT_Adwind_BD_MTB_2{
	meta:
		description = "TrojanDropper:WinNT/Adwind.BD!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 69 74 62 61 64 6b 77 61 64 2f 4d 6f 71 7a 68 62 6c 71 77 6d 78 } //1 mitbadkwad/Moqzhblqwmx
		$a_00_1 = {6c 77 68 75 6e 6a 67 66 64 78 2e 6a 73 } //1 lwhunjgfdx.js
		$a_00_2 = {72 65 73 6f 75 72 63 65 73 2f 63 7a 74 64 73 7a 64 65 7a 78 } //1 resources/cztdszdezx
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}