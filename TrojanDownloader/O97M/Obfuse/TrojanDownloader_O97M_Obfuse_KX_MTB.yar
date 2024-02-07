
rule TrojanDownloader_O97M_Obfuse_KX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.KX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 2e 6a 73 65 22 } //01 00  ".jse"
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 } //01 00  = Environ("USERPROFILE")
		$a_01_2 = {46 69 6c 65 4e 61 6d 65 3a 3d 22 74 65 73 74 5f 22 20 26 20 44 6f 63 4e 75 6d 20 26 20 22 2e 64 6f 63 22 } //01 00  FileName:="test_" & DocNum & ".doc"
		$a_01_3 = {55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 56 61 6c 75 65 } //01 00  UserForm1.TextBox1.Value
		$a_01_4 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 28 22 5c 53 65 63 74 69 6f 6e 22 29 2e 52 61 6e 67 65 2e 43 6f 70 79 } //01 00  ActiveDocument.Bookmarks("\Section").Range.Copy
		$a_01_5 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 28 73 74 61 72 74 29 } //00 00  .ShellExecute (start)
	condition:
		any of ($a_*)
 
}