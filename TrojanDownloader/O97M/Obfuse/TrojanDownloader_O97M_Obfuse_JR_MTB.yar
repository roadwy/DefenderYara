
rule TrojanDownloader_O97M_Obfuse_JR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 53 22 20 26 20 22 68 22 20 26 20 22 65 22 20 26 20 22 6c 22 20 26 20 22 6c 22 } //01 00  = "S" & "h" & "e" & "l" & "l"
		$a_01_1 = {3d 20 22 57 22 20 26 20 22 53 22 20 26 20 22 63 22 20 26 20 22 72 22 20 26 20 22 69 22 20 26 20 22 70 22 20 26 20 22 74 22 } //01 00  = "W" & "S" & "c" & "r" & "i" & "p" & "t"
		$a_01_2 = {3d 20 22 70 22 20 26 20 22 6f 22 20 26 20 22 77 22 20 26 20 22 65 22 20 26 20 22 72 22 20 26 20 22 73 22 20 26 20 22 68 22 20 26 20 22 65 22 20 26 20 22 6c 22 20 26 20 22 6c 22 20 26 20 22 2e 22 20 26 20 22 65 22 20 26 20 22 78 22 20 26 20 22 65 22 20 26 20 22 20 22 } //01 00  = "p" & "o" & "w" & "e" & "r" & "s" & "h" & "e" & "l" & "l" & "." & "e" & "x" & "e" & " "
		$a_01_3 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //01 00  = VBA.CreateObject(
		$a_01_4 = {2e 52 75 6e } //00 00  .Run
	condition:
		any of ($a_*)
 
}