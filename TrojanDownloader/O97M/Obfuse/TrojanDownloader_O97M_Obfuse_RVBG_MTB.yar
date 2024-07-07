
rule TrojanDownloader_O97M_Obfuse_RVBG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6c 71 4d 78 6a 2e 4f 70 65 6e 20 28 66 4e 61 64 76 20 2b 20 22 5c 47 5a 4e 47 58 2e 6a 73 22 29 } //1 plqMxj.Open (fNadv + "\GZNGX.js")
		$a_01_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 4f 4c 45 4f 62 6a 65 63 74 73 28 31 29 2e 43 6f 70 79 } //1 ActiveSheet.OLEObjects(1).Copy
		$a_01_2 = {70 6c 71 4d 78 6a 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6d 65 72 6d 6b 64 28 29 29 } //1 plqMxj = CreateObject(mermkd())
		$a_01_3 = {57 6f 72 6b 62 6f 6f 6b 5f 41 63 74 69 76 61 74 65 28 29 0d 0a 43 61 6c 6c 20 74 65 62 4b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}