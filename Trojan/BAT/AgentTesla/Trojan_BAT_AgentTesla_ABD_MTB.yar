
rule Trojan_BAT_AgentTesla_ABD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 b0 0b 00 00 95 2e 03 16 2b 01 17 7e 22 00 00 04 20 e4 0a 00 00 95 5a 7e 22 00 00 04 20 d9 08 00 00 95 58 61 81 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}
rule Trojan_BAT_AgentTesla_ABD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 07 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 6f 90 01 03 0a 06 16 06 8e 69 6f 90 01 03 0a 0c 08 8e 69 1f 10 59 8d 90 01 03 01 0d 08 1f 10 09 16 08 8e 69 1f 10 59 1f 10 58 1f 10 59 28 90 01 03 0a 09 90 00 } //5
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}