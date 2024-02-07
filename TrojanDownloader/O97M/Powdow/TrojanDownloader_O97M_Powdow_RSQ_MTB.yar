
rule TrojanDownloader_O97M_Powdow_RSQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 74 70 3a 2f 2f 72 65 62 72 61 6e 64 2e 6c 79 2f 57 64 42 50 41 70 6f 4d 41 43 52 4f } //01 00  ttp://rebrand.ly/WdBPApoMACRO
		$a_02_1 = {74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 34 71 32 79 34 61 66 6d 90 0a 1b 00 68 74 74 70 3a 2f 2f 90 00 } //01 00 
		$a_00_2 = {6c 6c 20 2d 77 20 31 20 2e 2f 61 2e 62 61 74 } //01 00  ll -w 1 ./a.bat
		$a_00_3 = {6d 6c 6b 6a 6c 6a 6b 6a 6c 6b 72 67 6c 6b 6a 67 72 66 6a 6b 6c 6a 67 66 72 76 } //00 00  mlkjljkjlkrglkjgrfjkljgfrv
	condition:
		any of ($a_*)
 
}