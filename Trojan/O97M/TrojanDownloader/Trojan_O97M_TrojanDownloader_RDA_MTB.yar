
rule Trojan_O97M_TrojanDownloader_RDA_MTB{
	meta:
		description = "Trojan:O97M/TrojanDownloader.RDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 31 39 32 2e 31 36 38 2e 34 31 2e 31 32 38 2f 70 6f 77 65 72 63 61 74 2e 70 73 31 } //01 00  //192.168.41.128/powercat.ps1
		$a_01_1 = {2d 70 20 31 33 33 37 } //01 00  -p 1337
		$a_01_2 = {2d 65 20 63 6d 64 } //00 00  -e cmd
	condition:
		any of ($a_*)
 
}