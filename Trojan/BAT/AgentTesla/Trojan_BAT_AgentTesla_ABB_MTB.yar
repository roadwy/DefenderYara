
rule Trojan_BAT_AgentTesla_ABB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {95 6e 31 03 16 2b 01 17 7e 11 00 00 04 18 9a 20 5d 0e 00 00 95 5a 7e 11 00 00 04 18 9a 20 34 07 00 00 95 58 61 81 07 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}