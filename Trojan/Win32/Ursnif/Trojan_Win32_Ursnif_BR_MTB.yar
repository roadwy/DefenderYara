
rule Trojan_Win32_Ursnif_BR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c8 0f b7 de 2b cf 8d b9 90 01 04 8b 0d 90 01 04 03 cb 89 3d 90 01 04 81 f9 90 01 04 75 90 00 } //01 00 
		$a_02_1 = {8b 4c 24 0c 83 c2 90 01 01 8b 5c 24 10 0f b7 c9 2b c8 03 d1 8b 1b 3d 90 01 04 75 90 00 } //01 00 
		$a_02_2 = {8b 4c 24 10 8d 34 55 90 01 01 00 00 00 81 c3 90 01 04 0f b7 c6 89 1d 90 01 04 66 89 35 90 01 04 89 19 8b 1d 90 01 04 3b d8 73 90 00 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}