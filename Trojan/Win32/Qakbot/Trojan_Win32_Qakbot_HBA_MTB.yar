
rule Trojan_Win32_Qakbot_HBA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 75 08 8b c1 83 e0 7f 8a 04 30 32 04 39 0f b6 c0 66 89 04 5a 43 41 3b 5d fc 72 } //01 00 
		$a_01_1 = {6d 6e 6a 68 75 69 76 34 30 } //01 00  mnjhuiv40
		$a_01_2 = {61 65 72 6f 66 6c 6f 74 } //01 00  aeroflot
		$a_01_3 = {4a 6a 69 73 63 68 75 67 } //01 00  Jjischug
		$a_01_4 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //00 00  DrawThemeIcon
	condition:
		any of ($a_*)
 
}