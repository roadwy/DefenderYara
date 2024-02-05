
rule Trojan_BAT_AgentTesla_MBBG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 02 0b 00 00 95 5f 11 3c 20 76 04 00 00 95 61 58 80 08 00 00 04 38 ef 00 00 00 7e 08 00 00 04 11 3c 20 e6 08 00 00 95 40 95 00 00 00 11 41 11 3c 20 cc 04 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}