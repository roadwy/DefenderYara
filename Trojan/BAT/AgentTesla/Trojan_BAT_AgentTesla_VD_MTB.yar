
rule Trojan_BAT_AgentTesla_VD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 0d 04 00 28 85 00 00 0a fe 0e 05 00 fe 0c 05 00 28 86 00 00 0a fe 0c 02 00 28 32 00 00 0a da fe 0e 06 00 fe 0c 03 00 fe 0c 06 00 28 87 00 00 0a 6f 88 00 00 0a 26 00 fe 0d 04 00 28 89 00 00 0a fe 0e 07 00 fe 0c 07 00 3a b2 ff ff ff } //5
		$a_01_1 = {53 00 63 00 69 00 5f 00 43 00 61 00 6c 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Sci_Cal.Resources
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}