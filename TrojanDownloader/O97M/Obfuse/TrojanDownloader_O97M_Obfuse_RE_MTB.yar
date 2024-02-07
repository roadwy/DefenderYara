
rule TrojanDownloader_O97M_Obfuse_RE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {24 45 4e 76 3a 70 75 62 6c 69 63 5c 90 02 08 2e 22 20 26 20 4d 6f 64 75 6c 65 31 2e 4d 30 39 30 20 26 20 22 90 00 } //01 00 
		$a_01_1 = {3d 20 22 65 78 65 22 } //01 00  = "exe"
		$a_01_2 = {22 44 6f 77 6e 4c 6f 41 64 66 49 6c 45 22 20 26 20 5f } //01 00  "DownLoAdfIlE" & _
		$a_01_3 = {3d 20 22 68 74 74 70 3a 2f 22 20 26 } //01 00  = "http:/" &
		$a_01_4 = {22 25 74 65 6d 70 25 22 20 26 } //01 00  "%temp%" &
		$a_03_5 = {43 61 6c 6c 20 53 68 65 6c 6c 28 90 02 20 20 26 20 22 20 22 20 26 90 00 } //01 00 
		$a_01_6 = {22 28 4e 45 77 2d 6f 62 6a 22 20 26 20 22 45 22 20 26 20 22 63 22 } //00 00  "(NEw-obj" & "E" & "c"
	condition:
		any of ($a_*)
 
}