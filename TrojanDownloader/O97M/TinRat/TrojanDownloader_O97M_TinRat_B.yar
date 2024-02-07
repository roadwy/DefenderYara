
rule TrojanDownloader_O97M_TinRat_B{
	meta:
		description = "TrojanDownloader:O97M/TinRat.B,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 6f 6e 2e 50 61 74 68 20 3d 20 22 77 6d 69 63 22 } //01 00  Action.Path = "wmic"
		$a_00_1 = {41 63 74 69 6f 6e 2e 41 72 67 75 6d 65 6e 74 73 20 3d 20 22 50 52 4f 43 45 53 53 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 22 77 73 63 72 69 70 74 2e 65 78 65 20 2f 62 20 2f 65 3a 6a 73 63 72 69 70 74 20 22 20 26 20 72 70 61 72 61 6d 20 26 20 22 5c 22 20 26 20 6c 70 61 72 61 6d 20 26 20 22 22 22 22 } //01 00  Action.Arguments = "PROCESS call create ""wscript.exe /b /e:jscript " & rparam & "\" & lparam & """"
		$a_00_2 = {62 65 65 5f 6a 65 20 22 61 75 74 6f 2e 63 68 6b 22 2c 20 6c 50 61 74 68 2c 20 22 53 79 73 75 70 64 61 74 65 5f 38 30 35 22 } //01 00  bee_je "auto.chk", lPath, "Sysupdate_805"
		$a_00_3 = {49 66 20 28 73 68 64 2e 4e 61 6d 65 20 3d 20 22 53 68 30 30 30 30 30 31 22 29 20 54 68 65 6e } //00 00  If (shd.Name = "Sh000001") Then
	condition:
		any of ($a_*)
 
}