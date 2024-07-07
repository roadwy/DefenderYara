
rule Trojan_BAT_AgentTesla_ABG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1b 9a 20 ba 04 00 00 95 2e 03 16 2b 01 17 7e 03 00 00 04 1b 9a 20 d8 04 00 00 95 5a 7e 03 00 00 04 1b 9a 1f 46 95 58 61 81 07 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_ABG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {25 07 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 25 07 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 0c 08 8e 69 1f 10 59 8d 90 01 03 01 0d 08 1f 10 09 16 08 8e 69 1f 10 59 28 90 01 03 0a 09 03 6b 90 00 } //5
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}