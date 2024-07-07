
rule Trojan_BAT_KillMBR_ARAU_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 11 07 11 07 11 07 1f 3e 5b 1f 14 5b 5a 59 11 07 61 d2 9c 11 07 17 58 13 07 11 07 11 06 8e 69 32 db } //5
		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  1
		$a_80_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  1
		$a_80_3 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //DisableRegistryTools  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}
rule Trojan_BAT_KillMBR_ARAU_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.ARAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 57 69 6e 44 65 61 74 68 5c 57 69 6e 44 65 61 74 68 5c 6f 62 6a 5c 44 65 62 75 67 5c 57 69 6e 44 65 61 74 68 2e 70 64 62 } //2 \WinDeath\WinDeath\obj\Debug\WinDeath.pdb
		$a_80_1 = {57 69 6e 64 6f 77 73 20 69 73 20 6e 6f 77 20 44 45 41 44 } //Windows is now DEAD  6
		$a_80_2 = {52 65 41 67 65 6e 74 63 2e 65 78 65 } //ReAgentc.exe  3
		$a_80_3 = {2f 64 69 73 61 62 6c 65 } ///disable  3
		$a_80_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //\\.\PhysicalDrive0  2
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*6+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*2) >=10
 
}