
rule Trojan_Win32_Vundo_gen_CF{
	meta:
		description = "Trojan:Win32/Vundo.gen!CF,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_02_0 = {8b c1 c1 e8 08 80 f9 c0 75 90 01 01 3c a8 74 90 00 } //01 00 
		$a_00_1 = {8b 08 50 1b db ff 51 28 3b } //01 00 
		$a_00_2 = {8b 08 1b db 50 8b eb ff 51 28 3b } //00 00 
	condition:
		any of ($a_*)
 
}