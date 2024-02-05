
rule Trojan_Win32_Ursnif_AV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f6 2b da 8b 15 90 01 04 1b d6 01 1d 90 01 04 8b 75 90 01 01 0f b7 c9 11 15 90 01 04 8b 54 24 90 01 01 8d 04 42 8d 84 08 90 01 04 0f af f8 03 f9 90 08 30 00 8d 41 90 01 01 81 c6 90 01 04 8b c8 2b 0d 90 01 04 89 75 00 83 c5 04 ff 4c 24 14 90 00 } //01 00 
		$a_02_1 = {0f b7 c8 8d 54 09 90 01 01 81 fa 90 01 04 7c 90 01 01 66 83 c0 90 01 01 66 a3 90 01 04 8b 7c 24 90 01 01 8b 4c 24 90 01 01 03 fe 13 cd 81 7c 24 90 01 05 89 0d 90 01 04 8b 0b 90 08 20 00 8b c6 2b 05 90 01 04 81 c1 90 01 04 89 0b 05 90 01 04 83 c3 04 ff 4c 24 90 01 01 66 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}