
rule Trojan_Win32_Alureon_BT{
	meta:
		description = "Trojan:Win32/Alureon.BT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 39 8d 44 24 04 68 04 01 00 00 50 ff 15 } //02 00 
		$a_01_1 = {66 8b 01 03 c2 8a 51 01 41 84 d2 75 e5 } //01 00 
		$a_01_2 = {3d ed 03 00 00 72 0f 77 08 81 f9 00 c0 10 d4 76 05 be 01 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}