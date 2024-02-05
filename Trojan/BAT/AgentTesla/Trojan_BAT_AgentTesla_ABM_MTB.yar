
rule Trojan_BAT_AgentTesla_ABM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {95 2e 03 16 2b 03 17 09 0d 17 59 09 0d 7e 0e 00 00 04 20 b6 00 00 00 95 5f 7e 0e 00 00 04 06 0a 20 79 01 00 00 95 61 58 81 07 00 00 01 } //04 00 
		$a_01_1 = {95 6e 31 03 16 2b 01 17 7e 32 00 00 04 16 9a 20 c2 11 00 00 95 5a 7e 32 00 00 04 16 9a 20 aa 0d 00 00 95 58 61 80 38 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}