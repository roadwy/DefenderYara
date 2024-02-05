
rule Trojan_Win32_Ursnif_BH_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 cb 03 d1 8d 0c 37 81 f9 90 08 15 00 83 c6 90 01 01 03 c8 03 ca 03 f1 8b 4c 24 90 01 01 0f b6 c9 81 f9 90 08 30 00 83 c2 90 01 01 8d 2c 06 8b fb 03 ea 0f af 3d 90 01 04 8b 54 24 90 01 01 2b 3d 90 01 04 8b 12 90 00 } //01 00 
		$a_02_1 = {03 de 89 54 24 90 01 01 89 15 90 01 04 be 04 00 00 00 39 74 90 01 02 89 11 8b 4c 24 90 01 01 0f b6 d1 0f b6 cb 0f 42 d1 89 1d 90 01 04 01 74 24 90 01 01 8a ca 0f b7 d7 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}