
rule TrojanDownloader_O97M_Qakbot_PUF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PUF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 72 53 65 72 76 65 72 } //01 00  erServer
		$a_01_1 = {72 75 6e 64 6c 6c 33 } //01 00  rundll3
		$a_01_2 = {55 52 4c 4d 6f 6e } //01 00  URLMon
		$a_01_3 = {33 31 2e 32 31 34 2e 31 35 37 2e 31 37 30 2f 32 32 2e } //00 00  31.214.157.170/22.
	condition:
		any of ($a_*)
 
}