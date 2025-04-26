
rule TrojanDownloader_O97M_Obfuse_RVCF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVCF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 65 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 68 6f 73 74 3d 22 68 74 74 70 3a 2f 2f 31 37 32 2e 31 30 34 2e 31 36 30 2e 31 32 36 3a 38 30 39 39 22 } //1 =environ("temp")host="http://172.104.160.126:8099"
		$a_01_1 = {3d 68 6f 73 74 2b 22 2f 70 61 79 6c 6f 61 64 32 2e 74 78 74 22 6d 61 6c 5f 65 6e 63 } //1 =host+"/payload2.txt"mal_enc
		$a_01_2 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 6f 62 6a 73 68 65 6c 6c 2e 72 75 6e 70 70 2c 30 2c 66 61 6c 73 65 65 6e 64 73 75 62 73 75 62 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 6d 61 69 6e 66 75 6e 63 65 6e 64 73 75 62 } //1 =createobject("wscript.shell")objshell.runpp,0,falseendsubsubdocument_open()mainfuncendsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}