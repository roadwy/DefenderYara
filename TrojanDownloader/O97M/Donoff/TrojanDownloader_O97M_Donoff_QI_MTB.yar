
rule TrojanDownloader_O97M_Donoff_QI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 73 73 68 32 5f 70 6f 6c 6c 20 4c 69 62 20 22 73 73 68 32 5f 70 6f 6c 6c 2e 64 6c 6c 22 } //1 Function ssh2_poll Lib "ssh2_poll.dll"
		$a_01_1 = {73 73 68 32 5f 70 6f 6c 6c 28 22 61 62 73 74 72 61 63 74 22 2c 20 35 29 } //1 ssh2_poll("abstract", 5)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}