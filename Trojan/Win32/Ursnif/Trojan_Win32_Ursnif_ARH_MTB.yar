
rule Trojan_Win32_Ursnif_ARH_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 ff 0f b6 05 90 01 04 0f b6 15 90 01 04 03 c2 89 44 24 90 01 01 3d 0f c6 00 00 74 90 00 } //01 00 
		$a_02_1 = {8b cf 2b ca 83 e9 90 01 01 ff 4c 24 90 01 01 0f 85 90 0a 25 00 0f b6 15 90 01 04 83 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}