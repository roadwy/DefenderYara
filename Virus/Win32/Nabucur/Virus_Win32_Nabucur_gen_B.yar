
rule Virus_Win32_Nabucur_gen_B{
	meta:
		description = "Virus:Win32/Nabucur.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_13_0 = {61 73 6b 6b 69 6c 6c 20 2f 46 49 20 22 55 53 45 52 4e 41 4d 45 20 65 71 20 4a 6f 68 6e 44 6f 65 22 20 2f 46 20 2f 49 4d 20 90 02 0b 2e 65 78 65 90 00 01 } //00 42 
		$a_54_1 = {68 00 65 00 72 00 65 00 } //20 00  here
		$a_00_2 = {72 00 65 00 20 00 74 00 77 00 6f 00 20 00 77 00 61 00 79 00 73 00 20 00 74 00 6f 00 20 00 70 00 61 00 79 00 20 00 61 00 20 00 66 00 69 00 6e 00 65 00 3a 00 01 00 12 00 0f c8 93 0f cb 87 de 0f ce 87 f7 0f cf 41 3b ca 75 ee 00 00 5d 04 00 00 b6 2b 03 80 5c 2c 00 00 b7 2b 03 80 00 00 01 00 2e } //00 16 
	condition:
		any of ($a_*)
 
}