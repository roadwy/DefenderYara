
rule TrojanDownloader_O97M_Obfuse_EQ{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.EQ,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_01_1 = {49 6e 6c 69 6e 65 53 68 61 70 65 73 28 32 29 2e 41 6c 74 65 72 6e 61 74 69 76 65 54 65 78 74 2c 20 30 } //1 InlineShapes(2).AlternativeText, 0
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 25 20 5f } //1 CreateObject("WScript.Shell").Run% _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}