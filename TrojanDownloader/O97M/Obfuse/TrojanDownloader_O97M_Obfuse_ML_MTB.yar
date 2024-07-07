
rule TrojanDownloader_O97M_Obfuse_ML_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ML!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 31 38 35 2e 32 34 33 2e 32 31 35 2e 32 31 33 2f 73 79 73 5f 69 6e 66 6f 2e 76 62 73 22 } //1 .Open "GET", "http://185.243.215.213/sys_info.vbs"
		$a_00_1 = {73 61 76 65 74 6f 66 69 6c 65 20 22 73 79 73 5f 69 6e 66 6f 2e 76 62 73 } //1 savetofile "sys_info.vbs
		$a_00_2 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 73 79 73 5f 69 6e 66 6f 2e 76 62 73 } //1 Shell "wscript sys_info.vbs
		$a_00_3 = {48 74 74 70 2e 53 65 6e 64 } //1 Http.Send
		$a_00_4 = {2e 77 72 69 74 65 20 78 48 74 74 70 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //1 .write xHttp.responseBody
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}