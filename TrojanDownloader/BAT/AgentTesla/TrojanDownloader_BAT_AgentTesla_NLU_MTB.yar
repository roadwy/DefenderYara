
rule TrojanDownloader_BAT_AgentTesla_NLU_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NLU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 1c 00 00 0a 25 72 11 00 00 70 6f 1d 00 00 0a 00 25 72 19 00 00 70 6f 1e 00 00 0a 00 25 17 6f 1f 00 00 0a 00 0a 2b 00 06 2a } //0a 00 
		$a_01_1 = {d0 21 00 00 01 28 19 00 00 0a 72 01 00 00 70 17 8d 14 00 00 01 25 16 d0 21 00 00 01 28 19 00 00 0a a2 28 1a 00 00 0a 14 17 8d 10 00 00 01 25 16 02 50 a2 6f 1b 00 00 0a 26 2a } //0a 00 
		$a_01_2 = {52 65 76 65 72 73 65 72 44 61 74 61 } //0a 00  ReverserData
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 73 } //0a 00  GetMethods
		$a_01_4 = {42 72 69 6e 67 54 6f 70 } //01 00  BringTop
		$a_80_5 = {53 61 7a 77 6c 73 71 75 75 6f 6c 68 77 6f 72 64 66 66 2e 41 65 68 64 7a 75 68 77 79 76 6f 74 6b } //Sazwlsquuolhwordff.Aehdzuhwyvotk  01 00 
		$a_80_6 = {46 74 71 6a 6f 67 64 69 2e 43 66 71 67 71 6f 66 } //Ftqjogdi.Cfqgqof  01 00 
		$a_80_7 = {50 71 66 6e 62 64 76 2e 59 79 66 79 6f 64 6f 65 6e 62 67 } //Pqfnbdv.Yyfyodoenbg  00 00 
	condition:
		any of ($a_*)
 
}