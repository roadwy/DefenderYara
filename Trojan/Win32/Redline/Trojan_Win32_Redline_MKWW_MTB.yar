
rule Trojan_Win32_Redline_MKWW_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 55 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 89 4d 90 01 01 c7 85 90 00 } //01 00 
		$a_03_1 = {c1 ea 05 89 55 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}