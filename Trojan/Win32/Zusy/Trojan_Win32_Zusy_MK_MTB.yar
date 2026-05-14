
rule Trojan_Win32_Zusy_MK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? ?? 00 00 40 0d 00 00 } //10
		$a_03_1 = {40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 ?? ?? 00 00 02 00 00 } //10
		$a_01_2 = {20 20 20 00 20 20 20 20 00 30 0d 00 00 10 00 00 00 38 06 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule Trojan_Win32_Zusy_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 04 8b 44 24 04 81 c1 d4 14 fa af 8a 84 04 3a 01 00 00 0f b6 d0 8b c2 23 c1 03 c0 2b d0 8b 44 24 04 03 d1 80 c2 34 88 94 04 3a 01 00 00 8b 44 24 04 40 89 44 24 04 83 7c 24 04 16 } //20
		$a_01_1 = {c7 84 24 20 04 00 00 a2 9a bd b4 c7 84 24 24 04 00 00 a0 9d b4 ac c7 84 24 28 04 00 00 a7 be b5 b8 c7 84 24 2c 04 00 00 b2 95 bb ba 66 c7 84 24 30 04 00 00 b9 ac c6 84 24 32 04 00 00 20 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}