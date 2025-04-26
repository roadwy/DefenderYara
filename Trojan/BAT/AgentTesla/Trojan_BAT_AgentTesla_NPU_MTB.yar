
rule Trojan_BAT_AgentTesla_NPU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {23 66 73 64 73 66 66 76 73 64 66 64 73 66 64 66 73 64 73 6c 6c 76 66 65 64 73 66 64 64 67 64 23 } //1 #fsdsffvsdfdsfdfsdsllvfedsfddgd#
		$a_01_1 = {23 67 66 66 64 73 64 73 64 66 73 66 73 73 73 65 64 6b 6a 64 66 66 2e 64 6c 6c 23 } //1 #gffdsdsdfsfsssedkjdff.dll#
		$a_01_2 = {23 64 64 73 66 64 66 64 73 66 64 73 66 67 73 64 76 73 64 3b 65 6f 64 66 6c 70 6c 6c 23 } //1 #ddsfdfdsfdsfgsdvsd;eodflpll#
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_01_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}