
rule TrojanDownloader_O97M_Obfuse_PRF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PRF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  CreateObject("WScript.shell")
		$a_00_1 = {6e 6e 71 2e 6e 6f 76 6f 6e 6f 72 64 69 73 6b 2e 63 6f 6d 5c 77 65 62 5c 4e 4e 53 4f 50 41 64 64 49 6e 5c 51 75 61 6c 69 74 79 44 6f 63 75 6d 65 6e 74 41 64 64 49 6e 5c 73 65 74 75 70 2e 65 78 65 } //01 00  nnq.novonordisk.com\web\NNSOPAddIn\QualityDocumentAddIn\setup.exe
		$a_03_2 = {2e 52 75 6e 20 28 90 02 19 29 90 00 } //01 00 
		$a_00_3 = {2e 5c 72 6f 6f 74 5c 64 65 66 61 75 6c 74 3a 53 74 64 52 65 67 50 72 6f 76 } //01 00  .\root\default:StdRegProv
		$a_03_4 = {2e 52 65 67 44 65 6c 65 74 65 20 28 90 02 0f 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}