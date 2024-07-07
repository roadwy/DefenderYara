
rule Trojan_BAT_Disstl_QQ_MTB{
	meta:
		description = "Trojan:BAT/Disstl.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c } ///C choice /C Y /N /D Y /T 1 & Del  3
		$a_80_1 = {64 69 73 63 6f 72 64 5f 6d 6f 64 75 6c 65 73 } //discord_modules  3
		$a_80_2 = {69 6e 64 65 78 2e 6a 73 } //index.js  3
		$a_80_3 = {65 6d 61 6e 72 65 73 75 } //emanresu  3
		$a_80_4 = {74 6c 75 61 66 65 44 5c 61 74 61 44 20 72 65 73 55 5c 65 6c 61 68 57 20 72 65 76 61 4e 5c 72 65 76 61 4e } //tluafeD\ataD resU\elahW revaN\revaN  3
		$a_80_5 = {79 72 61 6e 61 63 64 72 6f 63 73 69 64 } //yranacdrocsid  3
		$a_80_6 = {62 74 70 64 72 6f 63 73 69 64 } //btpdrocsid  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}