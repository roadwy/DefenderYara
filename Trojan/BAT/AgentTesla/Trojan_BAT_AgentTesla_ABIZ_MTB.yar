
rule Trojan_BAT_AgentTesla_ABIZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 08 17 8d 90 01 03 01 25 16 11 04 8c 90 01 03 01 a2 14 28 90 01 03 0a 28 90 01 03 0a 1f 10 28 90 01 03 0a 6f 90 01 03 0a 00 11 04 17 d6 13 04 00 11 04 20 90 01 03 00 fe 04 13 06 11 06 2d c0 90 00 } //5
		$a_01_1 = {43 00 6f 00 72 00 65 00 50 00 65 00 72 00 66 00 6f 00 72 00 6d 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 CorePerform.Resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}