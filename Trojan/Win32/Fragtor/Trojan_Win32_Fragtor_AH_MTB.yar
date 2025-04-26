
rule Trojan_Win32_Fragtor_AH_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b e5 5d 8a 08 30 0a 90 90 55 8b ec 83 c4 02 83 ec 02 83 c4 08 83 ec 08 83 c4 04 83 c4 fc 83 c4 03 83 ec 03 8b e5 90 5d 8a 08 00 0a } //3
		$a_01_1 = {55 8b ec 83 c4 06 83 c4 fa 83 c4 04 83 ec 04 56 5e 83 c4 04 83 c4 fc 8b e5 90 90 5d 42 90 55 90 90 8b ec 83 c4 03 83 c4 fd 41 49 83 c4 05 83 ec 05 83 c4 01 83 ec 01 8b e5 90 90 5d 40 4f 0f 85 } //3
		$a_01_2 = {50 88 55 c3 c6 45 b4 72 c6 45 b5 75 c6 45 b6 6e c6 45 b7 64 c6 45 b8 6c c6 45 b9 6c c6 45 ba 33 c6 45 bb 32 c6 45 bc 2e 88 5d bd c6 45 be 78 } //1
		$a_01_3 = {66 6f 72 6d 70 6c 61 74 } //1 formplat
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}