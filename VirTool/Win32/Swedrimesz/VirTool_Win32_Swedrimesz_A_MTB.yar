
rule VirTool_Win32_Swedrimesz_A_MTB{
	meta:
		description = "VirTool:Win32/Swedrimesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 18 8b 4c 24 1c e8 90 01 04 8d 90 01 02 89 44 24 24 33 f6 83 c4 04 83 7c 24 0c 02 8b fa 89 7c 24 1c 0f 45 f1 89 74 24 0c 85 90 00 } //1
		$a_03_1 = {8b f0 56 ff 15 90 01 04 50 68 70 47 40 00 e8 d4 90 01 03 83 c4 08 85 f6 0f 84 90 00 } //1
		$a_03_2 = {8b 5c 24 20 57 53 56 e8 26 90 01 03 83 c4 0c 57 6a 00 53 e8 b5 90 01 03 83 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}