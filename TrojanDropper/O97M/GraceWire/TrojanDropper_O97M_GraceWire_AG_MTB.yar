
rule TrojanDropper_O97M_GraceWire_AG_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 6c 57 2e 72 69 74 65 28 6f 75 74 66 70 2c } //01 00  Call lW.rite(outfp,
		$a_01_1 = {6f 75 74 70 75 74 2e 72 61 77 22 } //01 00  output.raw"
		$a_01_2 = {46 4d 4f 44 5f 45 72 72 6f } //01 00  FMOD_Erro
		$a_01_3 = {23 49 66 20 57 69 6e 36 34 20 41 6e 64 20 56 42 41 37 20 54 68 65 6e } //01 00  #If Win64 And VBA7 Then
		$a_03_4 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d 90 01 01 2e 54 65 78 74 42 6f 78 90 01 01 2e 54 61 67 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}