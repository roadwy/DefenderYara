
rule Ransom_Win32_Dircrypt_A{
	meta:
		description = "Ransom:Win32/Dircrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 00 3a 00 28 00 41 00 3b 00 4f 00 49 00 43 00 49 00 3b 00 47 00 41 00 3b 00 3b 00 3b 00 57 00 44 00 29 00 53 00 3a 00 28 00 4d 00 4c 00 3b 00 43 00 49 00 4f 00 49 00 3b 00 4e 00 52 00 4e 00 57 00 4e 00 58 00 3b 00 3b 00 3b 00 4c 00 57 00 29 00 } //01 00  D:(A;OICI;GA;;;WD)S:(ML;CIOI;NRNWNX;;;LW)
		$a_03_1 = {62 6f 74 69 64 00 90 02 08 70 61 79 69 6e 66 6f 00 90 00 } //01 00 
		$a_00_2 = {00 00 44 00 69 00 72 00 74 00 79 00 50 00 61 00 79 00 43 00 6f 00 64 00 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}