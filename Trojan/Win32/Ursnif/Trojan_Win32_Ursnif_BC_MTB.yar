
rule Trojan_Win32_Ursnif_BC_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 6f 72 6e } //01 00 
		$a_81_1 = {46 69 74 73 65 63 6f 6e 64 } //01 00 
		$a_81_2 = {50 61 73 74 70 75 74 } //01 00 
		$a_02_3 = {c1 e0 06 33 c9 03 05 90 01 04 8b 15 90 01 04 13 d1 90 02 11 83 c0 62 2b 05 90 01 04 33 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_BC_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b d0 0f b7 0d 90 01 04 03 d1 0f b7 05 90 01 04 03 c2 66 a3 90 01 04 8b 0d 90 01 04 81 c1 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 55 90 01 01 a1 90 01 04 89 82 90 00 } //01 00 
		$a_02_1 = {2b ca 88 0d 90 01 04 0f b7 05 90 01 04 0f b6 0d 90 08 20 00 0f b7 05 90 01 04 0f b6 0d 90 01 04 03 c1 2b 05 90 01 04 a2 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_BC_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.BC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 00 40 47 65 74 46 69 72 73 74 56 69 63 65 43 69 74 79 40 34 } //00 00 
	condition:
		any of ($a_*)
 
}