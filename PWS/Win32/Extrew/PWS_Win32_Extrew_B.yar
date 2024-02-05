
rule PWS_Win32_Extrew_B{
	meta:
		description = "PWS:Win32/Extrew.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff ff 77 75 3a 80 bd 90 01 02 ff ff 6f 75 31 80 bd 90 01 02 ff ff 77 75 28 80 bd 90 01 02 ff ff 2e 75 1f 80 bd 90 01 02 ff ff 65 90 00 } //01 00 
		$a_03_1 = {68 e8 03 00 00 ff 15 90 01 04 8b 75 90 01 01 81 fe 00 00 40 00 72 d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}