
rule Trojan_BAT_AgentTesla_BT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 fe 0e 01 00 20 03 00 00 00 fe 0e 05 00 00 fe 0c 05 00 20 06 00 00 00 fe 01 39 2a 00 00 00 fe 0d 04 00 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}