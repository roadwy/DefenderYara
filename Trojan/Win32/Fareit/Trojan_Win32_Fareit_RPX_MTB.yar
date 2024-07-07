
rule Trojan_Win32_Fareit_RPX_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5e fc 31 c9 81 c9 fc 1f 00 00 89 c7 51 f3 a4 59 81 34 08 90 01 04 83 e9 04 7d f4 ff e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 07 90 90 b0 29 90 90 30 07 8a 07 90 90 90 e8 } //1
		$a_01_1 = {90 90 43 81 fb 07 5d 00 00 75 b7 81 c6 34 08 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}