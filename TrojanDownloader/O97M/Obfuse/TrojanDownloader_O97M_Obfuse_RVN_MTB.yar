
rule TrojanDownloader_O97M_Obfuse_RVN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {6b 69 74 68 75 61 74 70 68 61 6e 6d 65 6d 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 63 68 61 72 65 2f 74 65 73 74 2e 7a 69 70 90 0a 53 00 6f 53 68 65 6c 6c 2e 52 75 6e 20 22 63 6d 64 2e 65 78 65 20 2f 63 20 63 75 72 6c 20 68 74 74 70 73 3a 2f 2f 90 00 } //01 00 
		$a_00_1 = {6f 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  oShell = CreateObject("WScript.Shell")
		$a_00_2 = {2d 2d 6f 75 74 70 75 74 20 44 3a 5c 7a 7a 2e 7a 69 70 22 2c 20 30 2c 20 46 61 6c 73 65 } //01 00  --output D:\zz.zip", 0, False
		$a_00_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65 } //00 00  Application.Visible = True
	condition:
		any of ($a_*)
 
}