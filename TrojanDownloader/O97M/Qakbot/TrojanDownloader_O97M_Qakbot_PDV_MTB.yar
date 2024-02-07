
rule TrojanDownloader_O97M_Qakbot_PDV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 45 67 68 65 6a 64 6f 72 2e 64 64 6c 6c 6c 6c } //01 00  \Eghejdor.ddllll
		$a_01_1 = {5c 45 67 68 65 6a 64 6f 72 31 2e 64 64 6c 6c 6c 6c } //01 00  \Eghejdor1.ddllll
		$a_01_2 = {5c 45 67 68 65 6a 64 6f 72 32 2e 64 64 6c 6c 6c 6c } //01 00  \Eghejdor2.ddllll
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //00 00  URLDownloadToFile
	condition:
		any of ($a_*)
 
}