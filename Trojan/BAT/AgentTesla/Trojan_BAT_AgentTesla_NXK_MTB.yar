
rule Trojan_BAT_AgentTesla_NXK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {35 34 35 42 47 47 50 37 39 54 50 35 4e 44 38 37 47 35 58 51 38 38 } //1 545BGGP79TP5ND87G5XQ88
		$a_81_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}