
rule TrojanDownloader_O97M_EncDoc_AIAX_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.AIAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 41 6f 74 5c 61 69 61 2e 6f 63 78 } //1 C:\Aot\aia.ocx
		$a_01_1 = {43 3a 5c 41 6f 74 5c 61 69 61 32 2e 6f 63 78 } //1 C:\Aot\aia2.ocx
		$a_01_2 = {43 3a 5c 41 6f 74 5c 61 69 61 31 2e 6f 63 78 } //1 C:\Aot\aia1.ocx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}