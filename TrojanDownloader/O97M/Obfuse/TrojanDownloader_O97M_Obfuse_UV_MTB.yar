
rule TrojanDownloader_O97M_Obfuse_UV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.UV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1  = CreateObject("WSCript.shell")
		$a_00_1 = {6c 69 6e 65 54 65 78 74 20 3d 20 73 69 6e 67 6c 65 4c 69 6e 65 2e 52 61 6e 67 65 2e 54 65 78 74 } //1 lineText = singleLine.Range.Text
		$a_03_2 = {52 65 70 6c 61 63 65 28 [0-19] 2c 20 22 [0-28] 22 2c 20 22 22 29 } //1
		$a_03_3 = {2e 52 75 6e 20 [0-19] 2c 20 32 20 2d 20 32 2e 31 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}