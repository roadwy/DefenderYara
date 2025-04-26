
rule TrojanDownloader_O97M_Obfuse_YD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 72 75 6f 72 74 20 3d 20 73 61 76 65 46 6f 6c 64 65 72 20 26 20 22 5c 47 65 72 74 6f 73 2e 63 6d 64 22 } //1 Hruort = saveFolder & "\Gertos.cmd"
		$a_00_1 = {73 74 72 54 65 6d 70 20 3d 20 43 68 72 24 28 56 61 6c 28 22 26 22 20 2b 20 22 48 22 20 2b 20 4d 69 64 24 28 42 69 6f 6c 61 2c 20 47 2c 20 32 29 29 29 } //1 strTemp = Chr$(Val("&" + "H" + Mid$(Biola, G, 2)))
		$a_00_2 = {73 61 76 65 46 6f 6c 64 65 72 20 3d 20 22 43 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 } //1 saveFolder = "C:\programdata
		$a_00_3 = {2e 50 61 74 68 20 26 20 22 5c 50 72 69 6d 65 72 2e 74 78 74 22 20 46 6f 72 20 49 6e 70 75 74 20 41 73 } //1 .Path & "\Primer.txt" For Input As
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}