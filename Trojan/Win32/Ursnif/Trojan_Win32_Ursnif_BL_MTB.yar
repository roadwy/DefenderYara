
rule Trojan_Win32_Ursnif_BL_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b7 fa 8b d8 2b d9 03 fe 83 eb 03 81 ff 90 01 04 8b 3d 90 01 04 89 1d 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8b 6c 24 10 8b c2 2b c1 81 c6 90 01 04 83 c0 90 01 01 89 75 00 83 c5 90 01 01 ff 4c 24 14 8d 4c 00 90 01 01 c7 05 90 01 04 00 00 00 00 0f b7 d1 89 6c 24 10 0f 85 90 01 02 ff ff 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}