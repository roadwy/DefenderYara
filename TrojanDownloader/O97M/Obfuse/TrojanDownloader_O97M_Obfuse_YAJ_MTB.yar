
rule TrojanDownloader_O97M_Obfuse_YAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 63 6f 64 65 42 61 73 65 36 34 28 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 } //1 DecodeBase64(Range("A3").Value
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 44 65 63 6f 64 65 42 61 73 65 36 34 28 52 61 6e 67 65 28 22 41 34 22 29 2e 56 61 6c 75 65 } //1 CreateObject(DecodeBase64(Range("A4").Value
		$a_01_2 = {62 69 6e 2e 62 61 73 65 36 34 22 3a 20 2e 74 65 78 74 20 3d 20 62 36 34 } //1 bin.base64": .text = b64
		$a_01_3 = {46 75 6e 63 74 69 6f 6e 20 44 65 63 6f 64 65 42 61 73 65 36 34 28 62 36 34 24 29 } //1 Function DecodeBase64(b64$)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}