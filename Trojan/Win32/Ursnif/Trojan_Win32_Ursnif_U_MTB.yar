
rule Trojan_Win32_Ursnif_U_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 0e 8a 85 90 01 04 8b 4d 04 34 90 01 01 88 41 90 00 } //01 00 
		$a_03_1 = {75 0f 8a 8d 90 01 04 8b 55 04 80 f1 90 01 01 88 4a 90 00 } //01 00 
		$a_01_2 = {c6 85 c4 a6 00 00 33 c6 85 c5 a6 00 00 30 c6 85 c6 a6 00 00 37 c6 85 c7 a6 00 00 37 c6 85 c8 a6 00 00 32 c6 85 c9 a6 00 00 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}