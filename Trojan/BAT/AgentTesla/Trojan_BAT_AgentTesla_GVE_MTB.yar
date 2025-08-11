
rule Trojan_BAT_AgentTesla_GVE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 ed 00 00 06 25 26 0b 12 01 28 c9 01 00 06 1f 18 28 26 00 00 06 5d 1f 1c 28 26 00 00 06 fe 01 2b 07 1f 20 28 26 00 00 06 0a 06 2c 08 00 28 05 00 00 06 00 00 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}