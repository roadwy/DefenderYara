
rule TrojanDropper_O97M_GraceWire_BU_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 4f 66 62 6c 20 3d 20 6f 66 62 6c 20 2b 20 73 65 6e 64 69 6e 67 73 43 53 54 52 20 2b 20 22 2e 64 6c 6c 22 90 02 05 43 6f 6d 70 6f 73 69 74 69 6f 6e 20 64 65 72 73 68 6c 65 70 20 26 20 4b 36 47 4f 41 4d 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 73 4f 66 62 6c 2c 20 43 75 72 72 65 6e 74 53 69 7a 65 4f 66 41 54 2c 20 73 65 6e 64 69 6e 67 73 90 00 } //01 00 
		$a_01_1 = {44 65 73 74 69 6e 61 74 69 6f 6e 4b 61 74 2e 43 6f 70 79 48 65 72 65 20 68 61 72 76 65 73 74 2e 49 74 65 6d 73 2e 49 74 65 6d 28 4b 36 47 4f 41 4d 2e 4c 61 62 65 6c 31 31 2e 54 61 67 29 } //01 00  DestinationKat.CopyHere harvest.Items.Item(K6GOAM.Label11.Tag)
		$a_03_2 = {44 6f 45 76 65 6e 74 73 90 0c 02 00 44 65 72 54 69 70 90 0c 02 00 44 6f 45 76 65 6e 74 73 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //01 00 
		$a_01_3 = {44 69 6d 20 41 63 74 69 76 65 48 6f 74 62 69 74 20 41 73 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //00 00  Dim ActiveHotbit As New WshShell
	condition:
		any of ($a_*)
 
}