
rule Trojan_BAT_AgentTesla_ABH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 e1 01 00 00 95 2e 03 16 2b 01 17 7e 0d 00 00 04 1b 9a 20 69 01 00 00 95 5a 7e 0d 00 00 04 1b 9a 20 c5 00 00 00 95 58 61 80 1d 00 00 04 } //02 00 
		$a_01_1 = {1a 9a 20 70 06 00 00 95 6e 09 0d 31 03 16 2b 01 17 7e 09 00 00 04 1a 9a 20 64 10 00 00 95 5a 7e 09 00 00 04 1a 9a 20 8d 0c 00 00 95 58 61 80 0c 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 b5 a2 3d 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 40 00 00 00 25 00 00 00 53 00 00 00 84 00 00 00 ca 00 00 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_5 = {47 65 74 52 75 6e 74 69 6d 65 44 69 72 65 63 74 6f 72 79 } //01 00  GetRuntimeDirectory
		$a_01_6 = {43 6f 6e 66 75 73 65 72 } //00 00  Confuser
	condition:
		any of ($a_*)
 
}