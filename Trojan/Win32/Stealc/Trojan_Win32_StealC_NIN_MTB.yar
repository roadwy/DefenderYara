
rule Trojan_Win32_StealC_NIN_MTB{
	meta:
		description = "Trojan:Win32/StealC.NIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 05 03 4c 24 2c 8b d0 c1 e2 04 03 54 24 28 03 c7 33 ca 33 c8 2b f1 8b ce c1 e1 04 c7 05 90 01 04 00 00 00 00 89 4c 24 90 00 } //1
		$a_03_1 = {8b c6 c1 e8 05 03 c5 33 c3 31 44 24 14 c7 05 90 01 04 19 36 6b ff c7 05 90 01 04 ff ff ff ff 8b 44 24 14 29 44 24 18 a1 b8 36 7c 00 3d 93 00 00 00 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}