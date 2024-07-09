
rule Trojan_BAT_AgentTesla_CAN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 04 8e 69 2f 25 11 04 11 05 9a 13 06 11 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 2e 07 11 06 6f ?? ?? ?? 0a 11 05 17 d6 13 05 2b d3 } //5
		$a_01_1 = {53 63 61 6e 6e 65 72 53 65 72 76 69 63 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 ScannerService.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AgentTesla_CAN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 3a 09 17 8d ?? 00 00 01 25 16 08 17 8d ?? 00 00 01 25 16 11 04 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 11 04 17 d6 13 04 00 11 04 } //4
		$a_01_1 = {53 70 6c 69 74 } //1 Split
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}