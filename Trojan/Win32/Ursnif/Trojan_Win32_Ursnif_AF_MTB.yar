
rule Trojan_Win32_Ursnif_AF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 54 24 10 2b ce 69 f6 90 01 04 05 90 01 04 2b de 89 02 83 c2 04 ff 4c 24 14 66 8b fb a3 90 01 03 00 66 89 3d 90 01 03 00 89 54 24 10 0f 85 90 01 02 ff ff 90 00 } //01 00 
		$a_02_1 = {8b 54 24 10 8b 12 89 15 90 01 03 00 13 fd 83 c3 f7 0f b7 d6 83 d7 ff 81 7c 24 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}