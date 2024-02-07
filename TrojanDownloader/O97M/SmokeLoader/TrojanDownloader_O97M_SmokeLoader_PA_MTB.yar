
rule TrojanDownloader_O97M_SmokeLoader_PA_MTB{
	meta:
		description = "TrojanDownloader:O97M/SmokeLoader.PA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 62 65 6d 6f 6a 6f 2e 63 6f 6d 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //01 00  https://bemojo.com/ds/161120.gif
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 62 74 63 68 73 2e 63 6f 6d 2e 62 72 2f 64 73 2f 31 36 31 31 32 30 2e 67 69 66 } //00 00  https://btchs.com.br/ds/161120.gif
	condition:
		any of ($a_*)
 
}