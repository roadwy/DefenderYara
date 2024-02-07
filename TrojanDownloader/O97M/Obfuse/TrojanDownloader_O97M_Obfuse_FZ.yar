
rule TrojanDownloader_O97M_Obfuse_FZ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FZ,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 75 73 22 20 26 20 22 65 72 6e 61 6d 65 22 29 20 26 20 22 5c 2e 74 65 6d 70 6c 61 74 65 73 22 } //01 00  C:\Users\" & Environ("us" & "ername") & "\.templates"
		$a_01_1 = {3d 20 22 65 22 20 26 20 22 78 22 } //01 00  = "e" & "x"
		$a_01_2 = {3d 20 22 53 79 73 74 65 6d 20 4d 61 6e 61 67 65 72 2e 22 20 26 20 65 65 65 65 20 26 20 22 65 22 } //01 00  = "System Manager." & eeee & "e"
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 62 20 26 20 22 63 68 22 20 26 20 73 61 20 26 20 22 6c 65 2e 22 20 26 20 73 67 20 26 20 73 6e 20 26 20 22 69 63 65 22 29 } //01 00  = CreateObject(sb & "ch" & sa & "le." & sg & sn & "ice")
		$a_01_4 = {66 73 6f 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 43 3a 5c 6f 75 74 2e 74 78 74 22 29 } //01 00  fso.CreateTextFile("C:\out.txt")
		$a_01_5 = {3d 20 42 61 73 65 36 34 44 65 63 6f 64 65 28 62 36 34 29 } //00 00  = Base64Decode(b64)
	condition:
		any of ($a_*)
 
}