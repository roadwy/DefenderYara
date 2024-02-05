
rule Trojan_BAT_AgentTesla_ABQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {95 6e 31 03 16 2b 01 17 7e 2a 00 00 04 19 9a 20 b1 00 00 00 95 5a 7e 2a 00 00 04 19 9a 20 22 0e 00 00 95 58 61 06 0a 81 05 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}