
rule Trojan_BAT_AgentTesla_CAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {16 9a 20 56 0b 00 00 95 6e 31 03 16 2b 01 17 17 59 11 34 16 9a 20 10 0d 00 00 95 5f 11 34 16 9a 20 64 03 00 00 95 61 58 80 43 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}