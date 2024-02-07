
rule Virus_Linux_Thus_gen_A{
	meta:
		description = "Virus:Linux/Thus.gen!A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 31 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 4c 69 6e 65 73 28 31 2c } //01 00  = ThisDocument.VBProject.VBComponents(1).CodeModule.Lines(1,
		$a_01_1 = {3d 20 4e 6f 72 6d 61 6c 54 65 6d 70 6c 61 74 65 2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 31 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 } //01 00  = NormalTemplate.VBProject.VBComponents(1).CodeModule
		$a_01_2 = {49 66 20 2e 4c 69 6e 65 73 28 31 2c 20 31 29 } //01 00  If .Lines(1, 1)
		$a_01_3 = {2e 44 65 6c 65 74 65 4c 69 6e 65 73 20 31 2c 20 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 } //01 00  .DeleteLines 1, .CountOfLines
		$a_01_4 = {2e 49 6e 73 65 72 74 4c 69 6e 65 73 20 31 2c } //00 00  .InsertLines 1,
	condition:
		any of ($a_*)
 
}