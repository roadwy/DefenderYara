
rule TrojanDownloader_O97M_Trilark_A_dha{
	meta:
		description = "TrojanDownloader:O97M/Trilark.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {73 68 65 6c 6c [0-03] 28 74 65 78 74 62 6f 78 [0-03] 2e 74 65 78 74 20 2b 20 74 65 78 74 62 6f 78 [0-03] 2e 74 65 78 74 20 2b 20 74 65 78 74 62 6f 78 [0-03] 2e 74 65 78 74 } //1
		$a_02_1 = {2e 74 65 78 74 20 2b 20 22 2e 22 20 2b 20 74 65 78 74 62 6f 78 [0-03] 2e 74 65 78 74 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}