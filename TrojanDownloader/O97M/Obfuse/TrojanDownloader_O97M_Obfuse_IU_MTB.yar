
rule TrojanDownloader_O97M_Obfuse_IU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 42 41 2e 53 68 65 6c 6c 20 28 52 69 67 68 74 28 22 49 6e 73 69 64 65 70 6f 77 65 72 22 2c 20 35 29 20 26 20 22 73 68 65 22 20 26 20 53 74 72 69 6e 67 28 32 2c 20 22 6c 22 29 20 26 20 22 20 77 73 22 20 26 20 4b 61 42 75 20 26 20 22 72 69 70 74 20 22 20 26 20 4b 61 73 7a 61 29 } //01 00  VBA.Shell (Right("Insidepower", 5) & "she" & String(2, "l") & " ws" & KaBu & "ript " & Kasza)
		$a_01_1 = {4b 61 73 7a 61 20 3d 20 22 2f 22 20 26 20 22 22 20 26 20 22 45 3a 4a 53 22 20 26 20 43 68 72 28 49 6e 74 33 29 20 26 20 22 72 69 70 54 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 4b 61 73 7a 61 20 26 20 43 68 72 28 33 34 29 } //01 00  Kasza = "/" & "" & "E:JS" & Chr(Int3) & "ripT " & Chr(34) & Kasza & Chr(34)
		$a_01_2 = {26 20 22 5c 6e 6f 72 6d 61 6c 2e 74 78 74 3a 24 2e 24 22 } //00 00  & "\normal.txt:$.$"
	condition:
		any of ($a_*)
 
}