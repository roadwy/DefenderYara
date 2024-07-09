
rule Trojan_BAT_Bladabindi_AH_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 07 00 00 "
		
	strings :
		$a_02_0 = {fa 25 33 00 16 ?? ?? 02 ?? ?? ?? 41 ?? ?? ?? 14 ?? ?? ?? 32 ?? ?? ?? 6a ?? ?? ?? 05 ?? ?? ?? 5e ?? ?? ?? 33 ?? ?? ?? 01 } //10
		$a_80_1 = {67 65 74 5f 46 75 6c 6c 4e 61 6d 65 } //get_FullName  3
		$a_80_2 = {67 65 74 5f 49 73 41 6c 69 76 65 } //get_IsAlive  3
		$a_80_3 = {49 73 4c 6f 67 67 69 6e 67 } //IsLogging  3
		$a_80_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  3
		$a_80_5 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //get_ExecutablePath  3
		$a_80_6 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //get_CurrentDomain  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=24
 
}