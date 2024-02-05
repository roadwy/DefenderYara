
rule Trojan_Win32_Redline_PZD_MTB{
	meta:
		description = "Trojan:Win32/Redline.PZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 7c 24 24 e8 90 01 04 01 6c 24 14 89 74 24 18 8b 44 24 20 01 44 24 18 8b 44 24 24 90 01 01 01 44 24 18 8b 44 24 18 89 44 24 1c 8b 54 24 1c 31 54 24 14 8b f7 c1 ee 05 03 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}