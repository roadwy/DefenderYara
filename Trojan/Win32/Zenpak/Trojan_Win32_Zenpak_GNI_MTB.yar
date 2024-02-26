
rule Trojan_Win32_Zenpak_GNI_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 e5 53 81 ec 90 01 04 89 e0 c7 00 90 01 04 a1 90 00 } //0a 00 
		$a_03_1 = {29 c2 83 c2 90 01 01 89 f8 50 8f 05 90 01 04 4a 89 2d 90 01 04 83 c2 90 01 01 89 f0 50 8f 05 90 01 04 8d 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}