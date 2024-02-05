
rule Trojan_Win32_Zenpak_GNS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 8d 14 37 8b cd 89 54 24 90 01 01 89 44 24 90 01 01 8d 44 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}