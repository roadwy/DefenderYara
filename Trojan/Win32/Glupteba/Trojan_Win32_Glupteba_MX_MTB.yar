
rule Trojan_Win32_Glupteba_MX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 03 e8 90 01 04 30 06 b8 01 00 00 00 29 44 24 90 01 01 8b 44 24 90 01 01 85 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 03 89 c9 88 06 01 f9 81 c7 90 01 04 46 81 e9 01 00 00 00 81 ef 90 01 04 81 c3 02 00 00 00 09 c9 29 f9 81 c1 7e 1a fc 72 39 d3 7e d1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_MX_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 56 8b 45 0c 89 45 fc 8b 0d 90 01 04 89 4d 08 68 90 01 04 ff 15 90 01 04 8b f0 03 75 fc 68 90 01 04 ff 15 90 01 04 03 f0 90 02 1a 8b 55 08 03 32 8b 45 08 89 30 5e 8b e5 5d c3 90 00 } //1
		$a_02_1 = {89 02 5f 5d c3 90 0a 29 00 33 d1 c7 05 90 02 08 8b c2 01 05 90 01 06 8b 15 90 01 04 a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}