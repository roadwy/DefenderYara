
rule Trojan_Win32_RedLine_RPQ_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 75 cc 3b f7 0f 83 81 00 00 00 8a 14 30 8b c6 83 e0 03 8a 88 90 01 04 32 ca 0f b6 da 8d 04 19 8b 4d d0 88 04 31 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_RedLine_RPQ_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 75 dc 3b f0 73 57 8b c6 83 e0 03 8a 88 90 01 04 32 0c 37 0f b6 1c 37 8d 04 19 88 04 37 90 00 } //1
		$a_01_1 = {83 c4 0c 28 1c 37 46 8b 45 d8 eb b9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_RedLine_RPQ_MTB_3{
	meta:
		description = "Trojan:Win32/RedLine.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5c 24 10 0f b6 1c 03 32 18 83 c0 04 88 5c 28 fc 8b 5c 24 14 0f b6 1c 0b 32 58 fd 83 c1 04 88 59 fc 0f b6 58 fe 32 5f ff 83 c7 04 88 59 fd 0f b6 58 ff 32 5f fc 83 6c 24 18 01 88 59 fe 75 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}