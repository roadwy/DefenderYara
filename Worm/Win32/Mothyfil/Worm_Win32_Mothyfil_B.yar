
rule Worm_Win32_Mothyfil_B{
	meta:
		description = "Worm:Win32/Mothyfil.B,SIGNATURE_TYPE_PEHSTR,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 63 6c 69 70 00 } //01 00  敳捴楬p
		$a_01_1 = {64 69 73 61 62 6c 65 69 74 00 } //01 00  楤慳汢楥t
		$a_01_2 = {70 75 73 73 79 43 6c 6f 73 65 00 } //01 00 
		$a_01_3 = {4b 69 6c 6c 61 70 70 00 } //01 00  楋汬灡p
		$a_01_4 = {77 68 61 74 5f 74 68 65 66 75 63 6b 00 } //01 00 
		$a_01_5 = {61 64 75 6c 74 6b 69 6c 6c 00 } //00 00  摡汵歴汩l
	condition:
		any of ($a_*)
 
}