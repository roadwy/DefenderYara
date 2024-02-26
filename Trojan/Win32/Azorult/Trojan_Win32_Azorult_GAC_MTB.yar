
rule Trojan_Win32_Azorult_GAC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 14 1f 89 55 90 01 01 8b d3 d3 ea c7 05 90 01 04 ee 3d ea f4 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 33 55 90 01 01 89 55 90 01 01 8b 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}