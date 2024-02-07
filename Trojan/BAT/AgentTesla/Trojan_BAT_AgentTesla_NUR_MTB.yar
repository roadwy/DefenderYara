
rule Trojan_BAT_AgentTesla_NUR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 df b6 eb 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 da 00 00 00 6e 00 00 00 17 01 00 00 90 03 00 00 85 01 00 00 23 00 00 00 9b 01 00 00 09 } //01 00 
		$a_01_1 = {54 46 6c 6f 77 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  TFlow.Properties.Resources.resources
		$a_01_2 = {56 00 55 00 57 00 55 00 65 00 64 00 66 00 64 00 6b 00 6a 00 6c 00 6a 00 6d 00 6a 00 6e 00 6a 00 } //00 00  VUWUedfdkjljmjnj
	condition:
		any of ($a_*)
 
}