
rule TrojanDownloader_BAT_AgentTesla_ABFA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8e 69 2b 19 16 2d f4 1e 2c e2 2b 18 2a 28 90 01 03 06 2b e5 0a 2b e4 06 2b e3 06 2b e3 28 90 01 03 0a 2b e0 06 2b e5 90 00 } //1
		$a_01_1 = {57 00 69 00 76 00 76 00 74 00 6b 00 66 00 71 00 63 00 7a 00 79 00 71 00 6b 00 7a 00 6c 00 70 00 73 00 2e 00 57 00 65 00 66 00 69 00 6e 00 75 00 75 00 61 00 72 00 76 00 79 00 6b 00 76 00 75 00 } //1 Wivvtkfqczyqkzlps.Wefinuuarvykvu
		$a_01_2 = {56 00 74 00 69 00 69 00 6a 00 72 00 69 00 6d 00 71 00 72 00 76 00 62 00 6c 00 6a 00 61 00 69 00 61 00 63 00 69 00 } //1 Vtiijrimqrvbljaiaci
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}