
rule Trojan_Win32_Guloader_RPL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d9 d0 33 04 32 [0-20] 35 [0-20] 90 13 [0-10] 8b 1c 24 [0-20] 01 04 33 [0-20] 83 ee 04 0f 8d ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_RPL_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 2c 17 f7 c2 [0-20] 90 13 [0-20] 90 13 [0-10] 81 f5 [0-20] 90 13 [0-20] 90 13 [0-10] 01 2c 10 [0-20] 90 13 [0-20] 90 13 [0-20] 90 13 83 da 04 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Guloader_RPL_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 0c 30 0f ae e8 de cb eb 4b } //1
		$a_01_1 = {9b 66 0f 61 d9 d8 d4 eb 48 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}