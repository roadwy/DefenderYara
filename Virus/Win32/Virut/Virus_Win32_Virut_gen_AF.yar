
rule Virus_Win32_Virut_gen_AF{
	meta:
		description = "Virus:Win32/Virut.gen!AF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 57 33 32 5f 56 69 72 74 75 } //01 00  \W32_Virtu
		$a_00_1 = {54 61 72 67 65 74 48 6f 73 74 00 } //01 00 
		$a_00_2 = {4a 4f 49 4e 20 26 76 69 72 74 75 } //01 00  JOIN &virtu
		$a_01_3 = {81 4a 24 60 00 00 e0 } //01 00 
		$a_01_4 = {c7 43 08 20 20 20 20 } //00 00 
	condition:
		any of ($a_*)
 
}