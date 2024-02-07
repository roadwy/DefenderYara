
rule TrojanDropper_O97M_Obfuse_QU_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.QU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 90 02 30 2e 65 78 65 22 90 00 } //01 00 
		$a_03_1 = {26 20 22 5c 90 02 08 2e 74 78 74 22 90 00 } //01 00 
		$a_01_2 = {66 69 6c 65 2e 77 72 69 74 65 6c 69 6e 65 20 28 54 65 78 74 42 6f 78 31 2e 54 65 78 74 29 } //01 00  file.writeline (TextBox1.Text)
		$a_03_3 = {2e 46 6f 6c 64 65 72 45 78 69 73 74 73 28 90 02 15 29 20 54 68 65 6e 90 00 } //01 00 
		$a_03_4 = {4f 70 65 6e 20 90 02 15 20 46 6f 72 20 49 6e 70 75 74 20 41 73 20 23 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}