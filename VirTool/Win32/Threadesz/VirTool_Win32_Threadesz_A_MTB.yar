
rule VirTool_Win32_Threadesz_A_MTB{
	meta:
		description = "VirTool:Win32/Threadesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 20 83 c4 0c 8b d6 57 53 8b 5c 24 24 53 ff 74 24 2c e8 90 01 04 83 c4 10 85 c0 75 90 00 } //1
		$a_03_1 = {89 45 d4 85 c0 0f 84 eb 00 00 00 53 53 53 53 53 53 50 ff 15 90 01 04 89 45 d0 85 c0 0f 84 90 00 } //1
		$a_03_2 = {50 6a 38 8d 90 01 02 50 57 53 ff 15 90 01 04 85 c0 75 90 00 } //1
		$a_03_3 = {8b fa 89 45 a0 8d 90 01 02 0f 11 45 c4 66 c7 45 d4 48 b9 c7 45 de 48 89 08 48 c7 45 e2 83 ec 40 e8 c7 45 e6 11 00 00 00 c6 45 ea 48 c7 45 ef 5b 41 5a 41 c7 45 f3 59 41 58 5a c7 45 f7 59 58 ff e0 c6 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}