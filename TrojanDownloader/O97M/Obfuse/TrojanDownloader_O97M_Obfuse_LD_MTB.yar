
rule TrojanDownloader_O97M_Obfuse_LD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {28 22 61 70 70 22 20 26 20 [0-08] 29 20 26 20 [0-10] 20 26 20 22 70 75 74 74 79 2e 73 63 72 22 } //1
		$a_01_1 = {2e 44 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 .DataType = "bin.base64"
		$a_01_2 = {2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //1 .createElement("b64")
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 45 72 72 6f 72 28 } //1 Debug.Print Error(
		$a_01_4 = {2e 54 65 78 74 20 3d } //1 .Text =
		$a_01_5 = {2e 6e 6f 64 65 54 79 70 65 64 56 61 6c 75 65 } //1 .nodeTypedValue
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}