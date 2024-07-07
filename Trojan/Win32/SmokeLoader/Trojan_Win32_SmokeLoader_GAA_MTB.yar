
rule Trojan_Win32_SmokeLoader_GAA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d0 c1 e2 04 03 d3 03 c8 33 d1 89 54 24 10 89 35 90 01 04 8b 44 24 24 01 05 90 01 04 8b 15 90 01 04 89 54 24 3c 89 74 24 24 8b 44 24 3c 01 44 24 24 8b 44 24 10 33 44 24 24 89 44 24 24 8b 44 24 24 90 00 } //1
		$a_03_1 = {33 c6 89 44 24 10 8b 44 24 24 31 44 24 10 8b 44 24 10 29 44 24 1c c7 44 24 20 00 00 00 00 8b 44 24 90 01 01 01 44 24 20 29 44 24 14 ff 4c 24 2c 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}