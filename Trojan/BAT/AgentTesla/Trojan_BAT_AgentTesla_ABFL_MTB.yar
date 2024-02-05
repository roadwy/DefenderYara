
rule Trojan_BAT_AgentTesla_ABFL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {7e f8 00 00 04 18 06 0c 9a 20 9a 11 00 00 95 5a 7e f8 00 00 04 18 9a 20 9c 00 00 00 95 58 61 80 bd 00 00 04 2a 7e bd 00 00 04 7e f8 00 00 04 18 9a 09 0c 20 b7 01 00 00 95 40 11 03 00 00 7e bd 00 00 04 7e f8 00 00 04 1b 9a } //00 00 
	condition:
		any of ($a_*)
 
}