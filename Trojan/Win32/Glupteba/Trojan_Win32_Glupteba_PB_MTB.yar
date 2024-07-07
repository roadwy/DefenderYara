
rule Trojan_Win32_Glupteba_PB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 90 02 04 8b 90 02 03 8b 90 02 03 33 90 01 01 33 90 01 01 8d 90 02 06 89 90 02 03 e8 90 02 04 8b 90 02 06 29 90 02 03 83 90 02 07 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_PB_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea 05 03 d5 03 c6 31 44 24 10 c7 05 90 01 08 c7 05 90 01 08 89 54 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 1c 8b 44 24 2c 29 44 24 18 4b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}