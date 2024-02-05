
rule Trojan_Win32_Redline_ZIM_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 55 90 01 01 89 45 08 8b 45 90 01 01 01 45 08 8b 45 08 33 45 90 01 01 33 d2 33 c1 50 89 45 08 90 00 } //01 00 
		$a_03_1 = {8b c1 c1 e8 90 01 01 03 45 90 01 01 03 f2 33 f0 33 75 90 01 01 c7 05 90 01 08 89 45 08 89 75 90 01 01 8b 45 90 01 01 29 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}