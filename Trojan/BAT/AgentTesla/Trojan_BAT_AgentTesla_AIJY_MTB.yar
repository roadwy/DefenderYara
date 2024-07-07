
rule Trojan_BAT_AgentTesla_AIJY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AIJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 07 11 0c 11 06 11 0c 9a 1f 10 } //2
		$a_01_1 = {9c 11 0c 17 58 13 0c 11 0c 11 06 8e 69 fe 04 13 0d 11 0d } //2
		$a_01_2 = {4d 61 69 6e 50 6c 61 79 65 72 4d 61 6e 61 67 65 6d 65 6e 74 46 6f 72 6d } //1 MainPlayerManagementForm
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}