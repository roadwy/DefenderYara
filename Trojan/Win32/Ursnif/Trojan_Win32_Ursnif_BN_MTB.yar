
rule Trojan_Win32_Ursnif_BN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b7 f3 8d 14 76 03 d0 2b ca 1b ff 8b d5 2b 15 90 01 04 83 ea 09 66 89 15 90 01 04 8b 54 24 10 8b 12 89 15 90 01 04 8b d1 2b d3 83 ea 09 66 89 15 90 01 04 3d 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8d 0c 06 03 e9 a1 90 01 04 8b 54 24 10 05 90 01 04 89 02 81 3d 90 01 08 89 2d 90 01 04 a3 90 00 } //01 00 
		$a_02_2 = {83 44 24 10 04 2b c6 2d 90 01 04 ff 4c 24 14 99 a3 90 01 04 89 15 90 01 04 0f 85 90 01 02 ff ff 90 00 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}