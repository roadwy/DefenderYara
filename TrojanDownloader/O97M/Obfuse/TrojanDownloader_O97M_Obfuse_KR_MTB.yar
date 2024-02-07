
rule TrojanDownloader_O97M_Obfuse_KR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 20 31 20 26 20 22 46 2e 77 6c 6c 22 } //01 00  + 1 & "F.wll"
		$a_03_1 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 14 29 20 53 74 65 70 20 32 3a 20 2e 57 72 69 74 65 20 43 68 72 28 43 42 79 74 65 28 22 26 48 22 20 26 20 4d 69 64 28 90 02 14 2c 20 6c 70 2c 20 32 29 29 29 3a 20 4e 65 78 74 3a 20 45 6e 64 20 57 69 74 68 3a 20 6f 62 6a 46 69 6c 65 2e 43 6c 6f 73 65 90 00 } //01 00 
		$a_01_2 = {4d 73 67 42 6f 78 20 22 54 68 65 20 64 6f 63 75 6d 65 6e 74 20 69 73 20 70 72 6f 74 65 63 74 65 64 2c 20 79 6f 75 20 77 69 6c 6c 20 6e 65 65 64 20 74 6f 20 73 70 65 63 69 66 79 20 61 20 70 61 73 73 77 6f 72 64 20 74 6f 20 75 6e 6c 6f 63 6b 2e 22 } //01 00  MsgBox "The document is protected, you will need to specify a password to unlock."
		$a_01_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 50 50 44 41 54 41 22 29 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 6f 72 64 5c 53 74 61 72 74 75 70 5c 22 } //01 00  = Environ("APPDATA") & "\Microsoft\Word\Startup\"
		$a_01_4 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 70 2c 20 54 72 75 65 29 } //01 00  .CreateTextFile(p, True)
		$a_01_5 = {2e 73 69 74 65 2f 73 68 61 72 65 2e 70 68 70 22 } //00 00  .site/share.php"
	condition:
		any of ($a_*)
 
}