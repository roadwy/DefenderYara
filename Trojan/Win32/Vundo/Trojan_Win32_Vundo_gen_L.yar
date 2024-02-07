
rule Trojan_Win32_Vundo_gen_L{
	meta:
		description = "Trojan:Win32/Vundo.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 e6 10 d2 70 } //01 00 
		$a_01_1 = {68 fe 6a 7a 69 } //02 00 
		$a_01_2 = {68 e1 1f f7 5a } //01 00 
		$a_01_3 = {68 62 67 8d a4 } //01 00 
		$a_01_4 = {68 5f 70 35 3a } //01 00  h_p5:
		$a_01_5 = {68 5a 6f de a9 } //01 00 
		$a_01_6 = {68 ee ea c0 1f } //01 00 
		$a_01_7 = {68 bd 4d 54 7d } //00 00 
	condition:
		any of ($a_*)
 
}