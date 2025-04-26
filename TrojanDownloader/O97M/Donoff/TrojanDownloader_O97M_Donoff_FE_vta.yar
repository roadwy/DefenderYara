
rule TrojanDownloader_O97M_Donoff_FE_vta{
	meta:
		description = "TrojanDownloader:O97M/Donoff.FE!vta,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 24 68 69 74 2b 24 6e 69 6d 2b 27 68 74 74 70 3a 2f 2f 6e 6f 6e 75 64 6f 6b 61 2e 74 6f 70 2f [0-10] 27 2b 24 66 6f 73 2b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}