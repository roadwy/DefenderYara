
rule Trojan_BAT_AgentTesla_PSCQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 23 73 ee 00 00 0a 13 04 2b 13 28 b9 00 00 0a 11 0c 16 11 0c 8e 69 6f f0 00 00 0a 13 04 11 0b 06 20 46 ff 1b 5d 61 07 61 19 } //05 00 
		$a_01_1 = {d1 28 eb 00 00 0a 26 11 06 28 ec 00 00 0a 6f ed 00 00 0a 13 31 18 13 08 11 08 16 73 e0 00 00 0a 13 13 7e 37 00 00 04 06 20 83 19 04 bd 58 07 61 11 08 60 61 } //00 00 
	condition:
		any of ($a_*)
 
}