
rule TrojanDownloader_O97M_Powdow_A{
	meta:
		description = "TrojanDownloader:O97M/Powdow.A,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 45 78 65 63 20 42 79 70 61 73 73 } //02 00  powershell.exe -NoP -NonI -W Hidden -Exec Bypass
		$a_01_1 = {49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e } //02 00  Invoke-Expression
		$a_01_2 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 5d 3a 3a 44 65 63 6f 6d 70 72 65 73 73 } //01 00  CompressionMode]::Decompress
		$a_01_3 = {49 4f 2e 4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  IO.MemoryStream
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //02 00  FromBase64String
		$a_03_5 = {53 68 65 6c 6c 20 28 90 05 0f 03 61 2d 7a 29 90 00 } //00 00 
		$a_00_6 = {5d 04 00 00 8b } //aa 03 
	condition:
		any of ($a_*)
 
}