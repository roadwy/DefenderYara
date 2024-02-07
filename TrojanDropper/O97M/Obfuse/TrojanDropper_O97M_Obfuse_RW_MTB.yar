
rule TrojanDropper_O97M_Obfuse_RW_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.RW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 } //01 00  Environ("Temp")
		$a_00_1 = {74 65 6d 70 46 6f 6c 64 65 72 50 61 74 68 20 26 20 22 5c 6d 61 67 69 63 2e 76 62 73 22 } //01 00  tempFolderPath & "\magic.vbs"
		$a_00_2 = {6d 61 67 69 63 50 6f 77 64 65 72 } //01 00  magicPowder
		$a_00_3 = {6d 61 67 69 63 46 69 6c 65 } //00 00  magicFile
	condition:
		any of ($a_*)
 
}