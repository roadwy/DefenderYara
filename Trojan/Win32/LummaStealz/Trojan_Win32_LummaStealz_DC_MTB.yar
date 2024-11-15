
rule Trojan_Win32_LummaStealz_DC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealz.DC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f3 a5 8b 74 24 f8 8b 7c 24 f4 8d 54 24 04 ff 54 24 fc c3 } //1
		$a_01_1 = {8b 44 24 48 8b 4c 24 48 0f b6 8c 0c e0 00 00 00 89 c2 83 c2 5a 21 ca 01 c8 01 d2 29 d0 05 5a 60 05 a7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}