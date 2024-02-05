
rule Trojan_BAT_AgentTesla_ABJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {18 9a 1f 39 95 2c 03 16 2b 01 17 17 59 7e 0e 00 00 04 20 f3 06 00 00 95 5f 7e 0e 00 00 04 1f 5e 95 61 58 81 05 00 00 01 } //02 00 
		$a_01_1 = {1f 11 95 7e 0e 00 00 04 20 cf 03 00 00 95 37 03 16 2b 01 17 17 59 7e 0e 00 00 04 20 96 01 00 00 95 5f 7e 0e 00 00 04 20 90 01 00 00 95 61 58 81 08 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}