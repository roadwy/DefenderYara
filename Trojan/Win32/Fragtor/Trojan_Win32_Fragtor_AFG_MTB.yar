
rule Trojan_Win32_Fragtor_AFG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 06 03 05 88 65 41 00 6a 00 6a 04 68 88 65 41 00 50 57 ff d3 83 c6 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fragtor_AFG_MTB_2{
	meta:
		description = "Trojan:Win32/Fragtor.AFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 05 70 48 01 10 a2 10 53 01 10 0f b6 05 71 48 01 10 a2 11 53 01 10 0f b6 05 72 48 01 10 a2 12 53 01 10 0f b6 05 73 48 01 10 a2 13 53 01 10 0f b6 05 74 48 01 10 a2 14 53 01 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}