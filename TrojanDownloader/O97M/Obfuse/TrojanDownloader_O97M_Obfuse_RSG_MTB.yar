
rule TrojanDownloader_O97M_Obfuse_RSG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_01_1 = {43 61 6c 6c 20 63 34 65 38 33 61 37 62 2e 65 78 65 63 28 61 39 35 31 38 61 66 64 29 } //1 Call c4e83a7b.exec(a9518afd)
		$a_01_2 = {62 64 61 63 35 31 31 61 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 62 61 65 64 63 31 65 37 28 31 29 2c 20 46 61 6c 73 65 } //1 bdac511a.Open "GET", baedc1e7(1), False
		$a_01_3 = {4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 36 30 } //1 MSXML2.XMLHTTP60
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}