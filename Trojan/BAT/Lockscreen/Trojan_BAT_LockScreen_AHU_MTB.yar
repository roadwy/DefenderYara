
rule Trojan_BAT_LockScreen_AHU_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.AHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 07 00 00 "
		
	strings :
		$a_02_0 = {0a 00 06 0b 16 0c 2b 21 07 08 9a 0d 00 72 ?? ?? ?? 70 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 26 09 6f ?? ?? ?? 0a 00 00 08 17 58 0c 08 07 8e 69 32 d9 } //10
		$a_80_1 = {44 49 53 41 42 4c 45 43 4d 44 5f 54 69 63 6b } //DISABLECMD_Tick  5
		$a_80_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  4
		$a_80_3 = {44 61 72 6b 43 72 79 70 74 } //DarkCrypt  4
		$a_80_4 = {50 72 6f 63 65 73 73 68 61 63 6b 65 72 2e 65 78 65 } //Processhacker.exe  3
		$a_80_5 = {72 65 67 65 64 69 74 2e 65 78 65 } //regedit.exe  3
		$a_80_6 = {43 42 54 52 57 45 36 4e 33 4e 56 35 4e 33 35 50 } //CBTRWE6N3NV5N35P  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=32
 
}