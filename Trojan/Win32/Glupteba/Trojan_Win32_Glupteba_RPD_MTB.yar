
rule Trojan_Win32_Glupteba_RPD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {39 ff 74 01 ea 31 39 90 01 04 81 c1 04 00 00 00 39 d1 75 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RPD_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d 08 8b 55 fc f7 da 8b 45 08 8b 08 2b ca 8b 55 08 89 0a 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}