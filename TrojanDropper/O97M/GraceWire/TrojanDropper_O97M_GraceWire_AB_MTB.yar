
rule TrojanDropper_O97M_GraceWire_AB_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 6c 57 2e 72 69 74 65 28 6f 75 74 66 70 2c } //01 00  Call lW.rite(outfp,
		$a_01_1 = {6f 75 74 70 75 74 2e 72 61 77 22 } //01 00  output.raw"
		$a_03_2 = {2b 20 22 2e 7a 90 02 14 69 90 02 14 70 22 90 00 } //01 00 
		$a_03_3 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d 90 01 01 2e 54 65 78 74 42 6f 78 90 01 01 2e 54 61 67 29 90 00 } //01 00 
		$a_01_4 = {3d 20 4d 73 67 42 6f 78 28 22 46 4d 4f 44 20 65 72 72 6f 72 21 20 28 22 20 26 20 72 65 73 75 6c 74 20 26 20 22 29 20 22 20 26 } //00 00  = MsgBox("FMOD error! (" & result & ") " &
	condition:
		any of ($a_*)
 
}