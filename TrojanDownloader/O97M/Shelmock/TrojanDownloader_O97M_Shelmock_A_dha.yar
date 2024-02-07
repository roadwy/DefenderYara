
rule TrojanDownloader_O97M_Shelmock_A_dha{
	meta:
		description = "TrojanDownloader:O97M/Shelmock.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 61 73 65 36 34 53 74 72 69 6e 67 28 5c 22 22 20 22 20 26 20 73 74 72 20 26 20 22 20 5c 22 22 20 29 } //01 00  Base64String(\"" " & str & " \"" )
		$a_00_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //01 00  powershell.exe
		$a_00_2 = {2d 4e 6f 50 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 45 78 65 63 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d } //01 00  -NoP -NonI -W Hidden -Exec Bypass -Comm
		$a_00_3 = {65 78 65 63 20 3d 20 65 78 65 63 20 2b 20 22 65 73 73 69 6f 6e 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 5d 3a 3a 44 65 63 6f 6d 70 72 65 73 73 29 29 2c 20 5b 54 65 78 74 2e 45 6e 63 22 } //01 00  exec = exec + "ession.CompressionMode]::Decompress)), [Text.Enc"
		$a_00_4 = {53 68 65 6c 6c 20 65 78 65 63 2c 20 76 62 48 69 64 65 } //00 00  Shell exec, vbHide
		$a_00_5 = {5d 04 00 } //00 28 
	condition:
		any of ($a_*)
 
}