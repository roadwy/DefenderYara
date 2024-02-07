
rule TrojanDownloader_O97M_Qakbot_PDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 63 61 6d 70 69 6e 67 6f 61 73 69 73 2e 63 6c 2f 6a 30 35 38 67 44 52 74 79 33 43 37 2f 36 2e 70 6e 22 26 22 67 } //01 00  ://campingoasis.cl/j058gDRty3C7/6.pn"&"g
		$a_01_1 = {3a 2f 2f 33 36 33 39 6f 70 74 69 63 61 6c 2e 67 61 2f 34 31 79 70 52 45 52 34 2f 36 2e 70 6e 22 26 22 67 } //01 00  ://3639optical.ga/41ypRER4/6.pn"&"g
		$a_01_2 = {3a 2f 2f 61 6d 70 64 75 63 74 77 6f 72 6b 2e 63 6f 6d 2f 65 4f 39 54 57 4e 41 55 7a 53 2f 36 2e 70 6e 22 26 22 67 } //00 00  ://ampductwork.com/eO9TWNAUzS/6.pn"&"g
	condition:
		any of ($a_*)
 
}