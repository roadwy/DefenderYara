
rule Virus_Win32_Patchload_gen_D{
	meta:
		description = "Virus:Win32/Patchload.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 47 65 74 90 03 01 01 50 00 90 00 } //01 00 
		$a_00_1 = {b8 47 65 74 50 } //01 00 
		$a_00_2 = {b8 72 6f 63 41 } //01 00 
		$a_00_3 = {b8 4c 69 62 72 } //01 00 
		$a_00_4 = {b8 4c 6f 61 64 } //01 00 
		$a_00_5 = {b8 6f 6c 65 2e } //00 00 
	condition:
		any of ($a_*)
 
}