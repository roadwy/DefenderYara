
rule TrojanDownloader_O97M_Obfuse_RSI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_01_1 = {43 61 6c 6c 20 63 35 61 33 32 34 34 65 2e 65 78 65 63 28 64 65 38 36 66 36 38 61 29 } //1 Call c5a3244e.exec(de86f68a)
		$a_01_2 = {61 30 65 31 61 35 36 31 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 66 38 61 33 30 31 61 65 28 31 29 2c 20 46 61 6c 73 65 } //1 a0e1a561.Open "GET", f8a301ae(1), False
		$a_01_3 = {53 70 6c 69 74 28 66 30 62 61 38 34 31 64 2c 20 22 7c 22 29 } //1 Split(f0ba841d, "|")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}