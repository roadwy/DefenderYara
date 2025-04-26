
rule TrojanDownloader_O97M_Obfuse_PE_MSR{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PE!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 [0-20] 68 74 74 70 [0-02] 3a 2f 2f [0-50] 2f 74 72 75 73 74 79 2f [0-30] 2e 70 6e 67 [0-10] 63 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c [0-10] 2e 65 78 65 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}