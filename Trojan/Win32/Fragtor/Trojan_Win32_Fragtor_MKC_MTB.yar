
rule Trojan_Win32_Fragtor_MKC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 48 f7 d0 89 05 06 b0 42 00 8b 15 68 3f 43 00 4a 81 f2 b3 0e 00 00 81 da 00 c0 00 02 89 15 8d 34 43 00 8b 15 8d 34 43 00 f7 d2 81 e2 e7 00 00 00 81 f2 00 00 b3 00 } //20
		$a_01_1 = {2d 01 18 e7 ca f7 d3 2d f9 05 00 00 4b f7 d3 f7 d9 4b 40 35 00 00 00 42 f7 d0 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}