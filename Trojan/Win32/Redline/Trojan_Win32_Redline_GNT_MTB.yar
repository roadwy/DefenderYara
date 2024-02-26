
rule Trojan_Win32_Redline_GNT_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 33 c0 80 2f 90 01 01 80 07 90 01 01 f6 2f 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GNT_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 4a 02 c1 e1 10 0f be 42 01 c1 e0 08 33 c8 0f be 02 33 c1 69 c0 90 01 04 33 f8 8b c7 c1 e8 0d 33 c7 69 c0 90 01 04 8b c8 c1 e9 0f 33 c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}