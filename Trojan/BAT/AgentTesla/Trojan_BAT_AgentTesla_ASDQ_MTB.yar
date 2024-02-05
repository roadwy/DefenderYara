
rule Trojan_BAT_AgentTesla_ASDQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 07 20 e8 03 00 00 73 90 01 01 00 00 0a 13 04 09 11 04 09 6f 90 01 01 00 00 0a 1e 5b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 09 11 04 09 6f 90 01 01 00 00 0a 1e 5b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 09 17 6f 90 01 01 00 00 0a 08 09 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 13 05 11 05 02 16 02 8e 69 6f 90 01 01 00 00 0a 11 05 6f 90 01 01 00 00 0a dd 90 00 } //01 00 
		$a_01_1 = {07 09 93 61 d1 9d 09 17 58 0d 09 06 32 } //00 00 
	condition:
		any of ($a_*)
 
}