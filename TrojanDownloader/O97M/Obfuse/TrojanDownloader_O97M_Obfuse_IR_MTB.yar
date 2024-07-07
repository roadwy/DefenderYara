
rule TrojanDownloader_O97M_Obfuse_IR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 10 28 65 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 90 02 09 2e 78 73 6c 22 2c 20 90 02 10 28 90 02 10 28 31 29 29 29 90 00 } //1
		$a_03_1 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 02 10 2c 20 90 02 10 2c 20 32 29 29 29 90 00 } //1
		$a_01_2 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //1 = New WshShell
		$a_01_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 63 65 70 74 41 6c 6c 52 65 76 69 73 69 6f 6e 73 } //1 ActiveDocument.AcceptAllRevisions
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}