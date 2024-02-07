
rule Ransom_Win32_Reveton_Q{
	meta:
		description = "Ransom:Win32/Reveton.Q,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 93 00 05 00 00 e8 90 01 04 a1 90 01 04 8a 93 00 06 00 00 88 10 a1 90 01 04 8a 93 01 06 00 00 88 10 a1 90 01 04 8b 93 02 06 00 00 89 10 90 00 } //01 00 
		$a_01_1 = {46 42 49 20 2d 20 43 6f 6d 70 75 74 65 72 20 6c 6f 63 6b 65 64 2e } //00 00  FBI - Computer locked.
		$a_00_2 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}