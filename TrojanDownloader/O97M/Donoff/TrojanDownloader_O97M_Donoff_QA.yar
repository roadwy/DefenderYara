
rule TrojanDownloader_O97M_Donoff_QA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QA,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 [0-04] 2e 65 22 20 26 20 22 78 65 22 2c 20 32 0d 0a 45 78 65 63 75 74 65 45 78 63 65 6c 34 4d 61 63 72 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}