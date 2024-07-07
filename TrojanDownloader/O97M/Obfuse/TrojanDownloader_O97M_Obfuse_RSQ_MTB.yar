
rule TrojanDownloader_O97M_Obfuse_RSQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 20 28 64 39 63 36 33 35 39 34 29 } //1 CreateObject("wscript.shell").exec (d9c63594)
		$a_01_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 66 33 30 63 39 34 61 36 2c 20 46 61 6c 73 65 } //1 .Open "GET", f30c94a6, False
		$a_01_2 = {53 70 6c 69 74 28 63 63 36 39 63 65 31 39 2c 20 22 7c 22 29 } //1 Split(cc69ce19, "|")
		$a_01_3 = {4f 70 65 6e 20 66 61 33 31 65 31 31 36 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1 Open fa31e116 For Output As #1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}