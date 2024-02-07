
rule Worm_Win32_Nerphun_gen_A{
	meta:
		description = "Worm:Win32/Nerphun.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 68 00 61 00 72 00 4f 00 6c 00 6e 00 69 00 4e 00 65 00 5c 00 50 00 72 00 6f 00 79 00 65 00 63 00 74 00 6f 00 31 00 2e 00 76 00 62 00 70 00 } //01 00  PharOlniNe\Proyecto1.vbp
		$a_01_1 = {44 65 63 6c 61 72 61 72 46 75 6e } //01 00  DeclararFun
		$a_01_2 = {4d 73 6e 53 70 72 65 61 64 65 72 } //01 00  MsnSpreader
		$a_01_3 = {48 00 65 00 79 00 20 00 21 00 21 00 20 00 6d 00 69 00 72 00 61 00 20 00 65 00 73 00 74 00 61 00 20 00 70 00 6f 00 73 00 74 00 61 00 6c 00 20 00 71 00 75 00 65 00 20 00 65 00 6e 00 63 00 6f 00 6e 00 74 00 72 00 65 00 20 00 70 00 61 00 72 00 61 00 20 00 74 00 69 00 20 00 3a 00 24 00 20 00 68 00 74 00 74 00 70 00 } //00 00  Hey !! mira esta postal que encontre para ti :$ http
	condition:
		any of ($a_*)
 
}