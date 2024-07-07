
rule Trojan_BAT_AgentTesla_GNL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 91 6f 90 01 03 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 2d e8 90 00 } //1
		$a_01_1 = {50 72 6f 67 72 65 73 73 69 76 65 } //1 Progressive
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}