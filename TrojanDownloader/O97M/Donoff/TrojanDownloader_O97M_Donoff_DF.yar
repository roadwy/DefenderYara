
rule TrojanDownloader_O97M_Donoff_DF{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DF,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 63 6d 64 2e 65 78 65 22 2c 20 70 72 6f 74 65 63 74 73 6f 75 74 68 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 30 } //01 00  .ShellExecute "cmd.exe", protectsouth, "", "open", 0
		$a_01_1 = {31 63 49 6d 47 64 51 2e 31 65 4b 78 4b 71 65 71 20 4c 2f 4c 76 63 7a 71 } //01 00  1cImGdQ.1eKxKqeq L/Lvczq
		$a_01_2 = {64 65 63 6c 69 6e 65 73 6f 6c 64 69 65 72 28 70 72 6f 74 65 63 74 73 6f 75 74 68 20 26 20 70 61 73 73 72 6f 6f 6d } //01 00  declinesoldier(protectsouth & passroom
		$a_01_3 = {47 49 2d 51 47 77 47 20 47 68 58 69 76 7a 64 7a 49 64 4b 65 4c 4c 6e 51 32 } //01 00  GI-QGwG GhXivzdzIdKeLLnQ2
		$a_01_4 = {7a 71 70 76 49 6f 32 51 77 51 47 65 48 51 72 49 73 49 68 51 4b 65 4c 31 6c 36 71 6c 71 2e } //00 00  zqpvIo2QwQGeHQrIsIhQKeL1l6qlq.
		$a_00_5 = {5d 04 00 } //00 ec 
	condition:
		any of ($a_*)
 
}