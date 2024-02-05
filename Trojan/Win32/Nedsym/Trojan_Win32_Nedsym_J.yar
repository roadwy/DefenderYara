
rule Trojan_Win32_Nedsym_J{
	meta:
		description = "Trojan:Win32/Nedsym.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 03 04 24 13 54 24 04 83 c4 08 8b d8 ff d3 8b d0 b8 90 01 04 e8 90 01 04 a1 90 01 04 80 38 22 90 00 } //01 00 
		$a_03_1 = {6a 00 6a 00 a1 90 01 04 e8 90 01 04 50 6a 00 e8 90 01 04 68 e8 03 00 00 e8 90 01 04 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}