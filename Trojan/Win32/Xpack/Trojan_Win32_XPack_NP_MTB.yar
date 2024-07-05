
rule Trojan_Win32_XPack_NP_MTB{
	meta:
		description = "Trojan:Win32/XPack.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 0d be 33 4c 00 03 0d 90 01 04 c1 e1 06 2b cb 81 f9 90 01 04 73 06 03 0d 90 01 04 c1 c9 02 29 0d 90 01 04 2b 0d 3f 32 90 00 } //01 00 
		$a_01_1 = {78 58 78 64 78 6a 78 } //00 00  xXxdxjx
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_XPack_NP_MTB_2{
	meta:
		description = "Trojan:Win32/XPack.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {29 c1 89 4c 24 90 01 01 8b 44 24 30 8b 4c 24 90 01 01 89 48 54 8b 44 24 90 01 01 8b 4c 24 30 90 00 } //03 00 
		$a_03_1 = {83 c1 58 81 fa 90 01 04 89 44 24 18 89 4c 24 90 01 01 72 00 8b 44 24 14 8b 4c 24 90 01 01 89 08 8b 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}