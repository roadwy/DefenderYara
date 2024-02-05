
rule Trojan_Win32_Ursnif_AW_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 c1 6b f8 90 01 01 0f b7 c3 03 c5 66 03 3d 90 01 04 66 89 3d 90 00 } //01 00 
		$a_02_1 = {0f b7 c7 6b d0 90 01 01 0f b7 cb 03 d1 89 54 24 90 01 01 89 15 90 01 04 99 2b f0 a1 90 01 04 1b c2 81 c6 90 01 04 83 d0 90 01 01 89 44 24 90 01 01 8b c1 90 00 } //01 00 
		$a_02_2 = {03 d8 8a 0d 90 01 04 8b 54 24 90 01 01 89 2e 8d 43 90 01 01 83 c6 04 66 a3 90 01 04 83 6c 24 90 01 02 89 74 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}