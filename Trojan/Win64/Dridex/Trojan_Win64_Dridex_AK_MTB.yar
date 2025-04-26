
rule Trojan_Win64_Dridex_AK_MTB{
	meta:
		description = "Trojan:Win64/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 44 54 42 47 2e 70 64 62 } //DDTBG.pdb  3
		$a_80_1 = {53 61 66 65 72 43 72 65 61 74 65 4c 65 76 65 6c } //SaferCreateLevel  3
		$a_80_2 = {43 4d 5f 47 65 74 5f 53 69 62 6c 69 6e 67 5f 45 78 } //CM_Get_Sibling_Ex  3
		$a_80_3 = {47 65 74 55 72 6c 43 61 63 68 65 45 6e 74 72 79 49 6e 66 6f 57 } //GetUrlCacheEntryInfoW  3
		$a_80_4 = {72 61 69 73 69 6e 67 6e 35 38 37 } //raisingn587  3
		$a_80_5 = {61 69 6e 63 6c 75 64 69 6e 67 31 70 } //aincluding1p  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}
rule Trojan_Win64_Dridex_AK_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 07 00 00 "
		
	strings :
		$a_81_0 = {4c 4f 47 4f 4e 53 45 52 56 45 52 } //3 LOGONSERVER
		$a_81_1 = {64 69 73 63 6f 72 64 61 70 70 } //3 discordapp
		$a_81_2 = {67 61 79 5f 6e 69 67 67 65 72 5f 70 6f 72 6e } //3 gay_nigger_porn
		$a_81_3 = {48 65 6c 6c 6f 57 6f 72 6c 64 58 6c 6c 2e 70 64 62 } //3 HelloWorldXll.pdb
		$a_81_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 57 } //3 ShellExecuteExW
		$a_81_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 } //3 URLDownloadToFileW
		$a_81_6 = {44 69 72 53 79 6e 63 53 63 68 65 64 75 6c 65 44 69 61 6c 6f 67 } //3 DirSyncScheduleDialog
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=20
 
}