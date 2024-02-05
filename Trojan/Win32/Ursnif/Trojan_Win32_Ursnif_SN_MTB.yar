
rule Trojan_Win32_Ursnif_SN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 00 0f b6 05 90 01 04 2b d1 83 c0 e1 83 ea 44 03 05 90 01 04 03 c3 89 15 90 01 04 8b 1d 90 01 04 a3 90 01 04 a1 90 01 04 05 4d fd fe ff 8b b4 3b c3 e0 ff ff 03 c2 a3 90 01 04 81 fd f1 72 8e 35 75 0d 0f b6 c2 6b c0 48 02 c1 a2 90 00 } //01 00 
		$a_03_1 = {81 c6 68 02 34 01 89 35 90 01 04 89 b4 3b c3 e0 ff ff 83 c7 04 8b 35 90 01 04 0f b6 0d 90 01 04 6b d6 48 03 d1 89 15 90 01 04 81 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_SN_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.SN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 0f b7 08 8b 45 f8 8b 40 1c 8d 04 88 8b 04 18 03 c3 ff d0 5f 5e 33 c0 5b 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}