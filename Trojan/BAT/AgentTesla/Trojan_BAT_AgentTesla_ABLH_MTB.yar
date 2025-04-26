
rule Trojan_BAT_AgentTesla_ABLH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 42 6f 6f 6b 50 72 6f 63 65 73 73 6f 72 2e 58 41 58 41 53 41 44 41 57 45 51 57 2e 72 65 73 6f 75 72 63 65 73 } //2 eBookProcessor.XAXASADAWEQW.resources
		$a_01_1 = {65 42 6f 6f 6b 50 72 6f 63 65 73 73 6f 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 eBookProcessor.Resources.resources
		$a_01_2 = {65 00 42 00 6f 00 6f 00 6b 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 } //1 eBookProcessor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}