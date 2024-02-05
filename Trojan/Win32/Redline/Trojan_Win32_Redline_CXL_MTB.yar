
rule Trojan_Win32_Redline_CXL_MTB{
	meta:
		description = "Trojan:Win32/Redline.CXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 c5 89 44 24 14 8b 44 24 1c 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 e8 90 01 04 8d 44 24 24 e8 90 01 04 83 ef 01 8b 4c 24 28 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}