
rule Trojan_Win32_Azorult_GFT_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 c5 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 8b 4c 24 90 01 01 33 4c 24 90 01 01 8d 44 24 90 01 01 89 4c 24 90 01 01 e8 90 01 04 8d 44 24 90 01 01 e8 90 01 04 83 ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}