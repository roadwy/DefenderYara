
rule Trojan_Win32_Ursnif_ARA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b d7 69 d2 90 01 04 2b d1 88 0d 90 01 04 89 15 90 01 04 03 c7 81 c6 dc 51 ed 01 8d 04 45 3a 00 00 00 89 35 90 01 04 89 b5 a4 e1 ff ff 0f b7 d8 0f b6 05 90 01 04 3d 90 01 04 75 16 90 00 } //01 00 
		$a_02_1 = {83 44 24 10 90 01 01 83 c7 90 01 01 03 fb 81 7c 24 90 01 05 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}