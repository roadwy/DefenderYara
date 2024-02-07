
rule Trojan_BAT_AgentTesla_AB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {20 c7 0b 00 00 95 2e 03 16 2b 04 17 06 13 04 17 59 7e 27 00 00 04 20 a3 11 00 00 95 5f 7e 27 00 00 04 20 d8 01 00 00 95 61 61 80 14 00 00 04 } //04 00 
		$a_01_1 = {20 b5 09 00 00 95 e0 95 7e 0a 00 00 04 20 b0 0c 00 00 95 61 7e 0a 00 00 04 20 cd 02 00 00 95 2e 03 17 2b 01 16 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {15 2d 0a 26 02 8e 69 16 2c 0a 26 2b 17 28 02 00 00 06 2b f0 0a 2b f4 28 01 00 00 06 02 06 91 6f 1e 00 00 0a 06 25 17 59 1b 2d 0a 26 16 fe 02 0b 07 2d e4 2b 03 0a 2b f4 } //03 00 
		$a_00_1 = {57 15 02 08 09 09 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 30 00 00 00 05 00 00 00 05 00 00 00 10 00 00 00 04 00 00 00 37 } //03 00 
		$a_81_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //03 00  SecurityProtocolType
		$a_81_3 = {57 65 62 52 65 71 75 65 73 74 } //00 00  WebRequest
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 65 6e 64 41 6c 6c 54 65 78 74 } //01 00  AppendAllText
		$a_01_1 = {57 72 69 74 65 41 6c 6c 54 65 78 74 } //01 00  WriteAllText
		$a_01_2 = {54 72 69 6d 45 6e 64 } //01 00  TrimEnd
		$a_01_3 = {54 72 61 6e 73 61 63 74 69 6f 6e } //01 00  Transaction
		$a_01_4 = {67 65 74 5f 43 75 72 72 65 6e 74 } //01 00  get_Current
		$a_01_5 = {67 65 74 5f 54 72 61 6e 73 61 63 74 69 6f 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e } //01 00  get_TransactionInformation
		$a_01_6 = {42 69 74 43 6f 6e 76 65 72 74 65 72 } //01 00  BitConverter
		$a_01_7 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_8 = {54 72 61 6e 73 61 63 74 69 6f 6e 61 6c 46 69 6c 65 4d 61 6e 61 67 65 72 2e 64 6c 6c } //00 00  TransactionalFileManager.dll
	condition:
		any of ($a_*)
 
}