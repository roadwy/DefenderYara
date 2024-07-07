
rule TrojanDropper_Win32_Krikun_A{
	meta:
		description = "TrojanDropper:Win32/Krikun.A,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 07 00 00 "
		
	strings :
		$a_00_0 = {2d 75 70 64 61 74 65 } //10 -update
		$a_00_1 = {53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 } //10 SeDebugPrivilege
		$a_00_2 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //10 CreateRemoteThread
		$a_00_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_02_4 = {8b 45 08 56 57 8b f1 90 90 66 3b 46 08 72 90 01 01 0f b7 f8 8b 06 90 00 } //1
		$a_00_5 = {57 50 ff d3 c6 45 e4 2e c6 45 e5 74 90 90 } //1
		$a_00_6 = {83 f8 08 77 08 8b 51 18 0f b6 32 eb 19 8b 51 18 83 f8 10 77 05 0f b7 32 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=42
 
}