
rule Virus_Linux_Linear{
	meta:
		description = "Virus:Linux/Linear,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {4f 70 65 6e 20 22 90 02 10 2e 63 6f 6d 22 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 90 00 } //01 00 
		$a_00_1 = {50 72 69 6e 74 20 23 } //01 00  Print #
		$a_00_2 = {43 6c 6f 73 65 20 23 } //01 00  Close #
		$a_00_3 = {3d 20 53 68 65 6c 6c 28 22 } //01 00  = Shell("
		$a_00_4 = {2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 31 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 69 6e 73 65 72 74 6c 69 6e 65 73 } //01 00  .VBProject.VBComponents(1).CodeModule.insertlines
		$a_00_5 = {2e 56 42 50 72 6f 6a 65 63 74 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 31 29 2e 43 6f 64 65 4d 6f 64 75 6c 65 2e 64 65 6c 65 74 65 6c 69 6e 65 73 } //01 00  .VBProject.VBComponents(1).CodeModule.deletelines
		$a_00_6 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 6f 77 56 69 73 75 61 6c 42 61 73 69 63 45 64 69 74 6f 72 20 3d 20 30 } //01 00  Application.ShowVisualBasicEditor = 0
		$a_00_7 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 45 6e 61 62 6c 65 43 61 6e 63 65 6c 4b 65 79 20 3d 20 30 } //01 00  Application.EnableCancelKey = 0
		$a_00_8 = {50 72 69 76 61 74 65 20 53 75 62 20 56 69 65 77 56 42 43 6f 64 65 28 29 } //01 00  Private Sub ViewVBCode()
		$a_00_9 = {50 72 69 76 61 74 65 20 53 75 62 20 54 6f 6f 6c 73 4d 61 63 72 6f 28 29 } //00 00  Private Sub ToolsMacro()
	condition:
		any of ($a_*)
 
}