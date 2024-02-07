
rule Trojan_BAT_AgentTesla_DAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 18 2b 1d 1e 2c f9 2b 1b 2b 20 2b 21 2b 26 2b 2b 2b 30 2b 35 1d 2c ec de 39 28 90 01 01 00 00 06 2b e1 0a 2b e0 28 90 01 01 00 00 0a 2b de 06 2b dd 6f 90 01 01 00 00 0a 2b d8 28 90 01 01 00 00 0a 2b d3 28 90 01 01 00 00 2b 2b ce 28 90 01 01 00 00 2b 2b c9 0b 2b c8 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_DAS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 64 44 50 4b 44 7c 45 54 5d 44 5c 49 44 6a 44 54 68 44 7a 4a 44 6c 45 54 65 44 58 4a 44 7d 45 7a 66 44 48 48 44 45 44 44 46 44 6a 47 44 44 44 } //01 00  TdDPKD|ET]D\IDjDThDzJDlETeDXJD}EzfDHHDEDDFDjGDDD
		$a_01_1 = {54 64 44 54 4b 44 76 45 54 67 44 33 48 44 44 44 44 44 44 58 4a 44 77 45 54 5c 44 37 48 44 33 45 7a 5c 44 58 4b 44 6e 45 7a 65 44 4c 4b 44 54 45 } //01 00  TdDTKDvETgD3HDDDDDDXJDwET\D7HD3Ez\DXKDnEzeDLKDTE
		$a_01_2 = {44 44 44 44 37 4a 44 79 45 54 64 44 50 4b 44 7c 45 54 5d 44 5c 49 44 6a 44 } //01 00  DDDD7JDyETdDPKD|ET]D\IDjD
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {54 6f 53 74 72 69 6e 67 } //00 00  ToString
	condition:
		any of ($a_*)
 
}