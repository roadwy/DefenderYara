
rule Trojan_Win32_StealC_GF_MTB{
	meta:
		description = "Trojan:Win32/StealC.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 31 45 fc 8b 45 fc 89 45 e4 89 75 f0 8b 45 e4 89 45 f0 8b 45 f8 31 45 f0 8b 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_StealC_GF_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 e9 19 04 00 00 89 4d fc 83 7d fc 2a 77 41 8b 55 fc 0f b6 82 90 62 41 00 ff 24 85 78 62 41 00 } //2
		$a_01_1 = {8b 08 69 c9 0b a3 14 00 81 e9 51 75 42 69 8b 55 08 } //2
		$a_01_2 = {72 09 81 7d f8 57 04 00 00 73 08 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}