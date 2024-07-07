
rule Trojan_Win32_Dridex_B{
	meta:
		description = "Trojan:Win32/Dridex.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 45 c4 b1 10 66 8b 55 d2 66 81 e2 90 01 02 66 89 55 d2 8a 2c 05 90 01 04 8b 75 cc 29 f6 89 75 d4 28 e9 02 0c 05 90 01 04 88 4c 05 d8 83 c0 01 83 f8 0e 89 45 c4 75 c7 90 00 } //5
		$a_02_1 = {8b 45 88 b1 39 8a 14 05 90 01 04 66 c7 45 d4 88 65 28 d1 02 0c 05 90 01 04 88 4c 05 dc 83 c0 01 83 f8 0e 89 45 88 74 cf eb d4 90 00 } //5
		$a_00_2 = {4c 43 cf 8a 5f 49 4c 43 cf 8a 5f 49 4c 43 cf 8a } //2
		$a_00_3 = {49 70 61 45 31 54 79 6c 4a 78 2e 70 64 62 } //3 IpaE1TylJx.pdb
	condition:
		((#a_02_0  & 1)*5+(#a_02_1  & 1)*5+(#a_00_2  & 1)*2+(#a_00_3  & 1)*3) >=5
 
}