
rule Trojan_Win32_Ursnif_SQ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 14 8d 6a fa 03 eb 03 c1 89 6c 24 2c } //01 00 
		$a_03_1 = {8b 6c 24 14 8b 54 24 24 81 c5 cc 9d e5 01 66 39 74 24 12 89 28 0f b6 c3 0f b6 d2 0f 42 d0 89 1d 90 01 04 83 44 24 18 04 0f b7 c7 8d 79 fa 03 f8 89 6c 24 14 ff 4c 24 28 89 2d 90 01 04 89 54 24 24 88 15 90 01 04 74 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}