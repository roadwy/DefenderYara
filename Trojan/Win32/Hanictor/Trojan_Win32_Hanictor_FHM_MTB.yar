
rule Trojan_Win32_Hanictor_FHM_MTB{
	meta:
		description = "Trojan:Win32/Hanictor.FHM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b c0 44 8b 0d 04 60 04 01 2b c8 0f b7 55 f8 2b d1 66 89 55 f8 a1 04 60 04 01 33 c9 03 05 58 60 04 01 8b 15 5c 60 04 01 13 d1 a3 58 60 04 01 89 15 5c 60 04 01 a1 dc 60 04 01 83 e8 09 2b 05 04 60 04 01 66 89 45 f8 } //1
		$a_01_1 = {53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}