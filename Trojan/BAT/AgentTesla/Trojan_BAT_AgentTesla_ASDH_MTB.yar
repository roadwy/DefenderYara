
rule Trojan_BAT_AgentTesla_ASDH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 4a 61 d2 61 d2 52 20 90 01 01 00 00 00 fe 0e 0a 00 00 fe 0c 0a 00 20 90 01 01 00 00 00 fe 01 39 90 00 } //1
		$a_03_1 = {25 47 fe 0c 01 00 fe 0c 02 00 91 61 d2 52 20 90 01 01 00 00 00 fe 0e 0a 00 00 fe 0c 0a 00 20 90 01 01 00 00 00 fe 01 39 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}