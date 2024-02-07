
rule TrojanDownloader_O97M_Obfuse_RSF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 44 3a 22 20 26 20 22 5c 32 32 32 2e 65 78 65 22 20 46 6f 72 20 42 69 6e 61 72 79 20 41 73 20 23 46 72 65 65 46 } //01 00  Open "D:" & "\222.exe" For Binary As #FreeF
		$a_01_1 = {4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6e 76 69 64 69 61 78 2e 65 78 65 22 } //01 00  Open Environ("temp") & "\nvidiax.exe"
		$a_01_2 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 74 61 73 6b 67 68 6f 73 74 2e 65 78 65 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //01 00  Shell Environ("temp") & "\taskghost.exe", vbNormalFocus
		$a_01_3 = {20 4d 69 64 28 53 2c 20 63 2c 20 36 30 30 29 } //01 00   Mid(S, c, 600)
		$a_01_4 = {20 6f 62 6a 58 4d 4c 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //00 00   objXML.createElement("b64")
	condition:
		any of ($a_*)
 
}