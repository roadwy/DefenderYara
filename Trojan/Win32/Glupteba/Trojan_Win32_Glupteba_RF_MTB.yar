
rule Trojan_Win32_Glupteba_RF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 86 72 18 5f 46 89 ff e8 90 01 04 01 f7 47 31 02 81 ee 01 00 00 00 81 c2 01 00 00 00 81 ef 9a f8 1a ff 4e 39 da 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Glupteba_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Glupteba.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 89 44 24 90 01 01 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8d 14 37 31 54 24 90 01 01 81 3d 90 01 04 f5 03 00 00 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}