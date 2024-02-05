
rule Trojan_Win32_Ursnif_ARD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 f8 8b 44 24 90 01 01 3b c7 74 90 01 01 8b df 0f af d9 6b db 90 01 01 03 c3 89 44 24 90 01 01 81 ff 90 01 04 74 90 01 01 b3 90 01 01 f6 eb 83 c6 90 01 01 02 c1 81 fe 90 01 04 7c 90 00 } //01 00 
		$a_02_1 = {33 ff 2b e8 6a 90 01 01 58 1b c7 03 cd 66 8b 2d 90 01 04 13 d0 8b c1 89 15 90 01 04 6b c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}