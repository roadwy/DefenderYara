
rule Trojan_Win32_RedLineStealer_PU_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 44 24 90 01 01 33 44 24 90 01 01 89 74 24 90 01 01 89 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLineStealer_PU_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 40 47 4e c7 84 24 90 01 04 1a 41 9f 17 c7 84 24 90 01 04 44 55 93 01 c7 84 24 90 01 04 79 16 54 13 c7 84 24 90 01 04 7f 0c 54 3c c7 84 24 90 01 04 f8 dc bd 0f c7 84 24 90 01 04 37 1e d5 38 90 00 } //1
		$a_01_1 = {f7 a4 24 80 00 00 00 8b 84 24 80 00 00 00 81 ac 24 80 00 00 00 d6 8a cd 68 b8 e2 3f 96 6e f7 a4 24 80 00 00 00 8b 84 24 80 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}