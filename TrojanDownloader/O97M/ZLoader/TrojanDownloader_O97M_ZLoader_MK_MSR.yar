
rule TrojanDownloader_O97M_ZLoader_MK_MSR{
	meta:
		description = "TrojanDownloader:O97M/ZLoader.MK!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {63 3a 5c 70 69 70 65 64 69 72 5c 90 02 15 2e 76 62 73 20 68 74 74 70 3a 2f 2f 32 30 35 2e 31 38 35 2e 31 32 32 2e 32 34 36 2f 66 69 6c 65 73 2f 90 02 05 2e 65 78 65 20 63 3a 5c 70 69 70 65 64 69 72 5c 90 02 15 2e 65 78 65 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}