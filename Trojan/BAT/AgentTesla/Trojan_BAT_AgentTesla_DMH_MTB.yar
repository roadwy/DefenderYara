
rule Trojan_BAT_AgentTesla_DMH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_01_2 = {00 47 65 74 54 79 70 65 00 } //01 00 
		$a_01_3 = {00 43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 00 } //01 00 
		$a_01_4 = {20 00 54 00 20 00 20 00 6f 00 20 00 57 00 20 00 69 00 20 00 6e 00 20 00 33 00 20 00 32 00 20 00 } //01 00   T  o W i n 3 2 
		$a_01_5 = {54 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 54 00 78 00 46 00 69 00 6c 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //01 00  Transactions.TxFileManager
		$a_01_6 = {00 47 65 74 50 69 78 65 6c 00 } //01 00  䜀瑥楐數l
		$a_01_7 = {00 69 73 4f 4b 00 } //00 00  椀佳K
	condition:
		any of ($a_*)
 
}