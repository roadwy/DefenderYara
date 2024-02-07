
rule TrojanDownloader_O97M_Qakbot_RV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 64 6f 6d 6f 70 6f 72 74 75 67 61 6c 2e 63 6f 6d 2f 61 62 72 76 6d 66 2f 35 35 35 35 35 35 35 35 35 35 2e 6a 70 67 } //01 00  www.domoportugal.com/abrvmf/5555555555.jpg
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 20 30 2c 20 47 75 69 6b 67 68 6a 67 66 68 2c 20 42 74 64 75 66 6a 6b 68 6e 2c 20 30 2c 20 30 } //01 00  URLDownloadToFile 0, Guikghjgfh, Btdufjkhn, 0, 0
		$a_00_2 = {4c 6f 73 65 72 20 3d 20 22 68 74 74 70 3a 2f 2f 22 } //00 00  Loser = "http://"
	condition:
		any of ($a_*)
 
}