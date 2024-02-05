
rule Trojan_BAT_AgentTesla_SN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_02_0 = {0d 11 04 20 90 01 04 5a 20 90 01 04 61 90 0a f0 00 07 17 7e 90 01 04 a2 06 6f 90 01 04 16 9a 6f 90 01 04 19 9a 14 07 6f 90 01 04 0c 72 90 00 } //02 00 
		$a_02_1 = {0b 11 04 20 90 01 04 5a 20 90 01 04 61 38 90 0a f0 00 72 90 01 04 28 90 01 04 28 90 01 04 72 90 01 04 20 00 01 00 00 14 14 17 8d 90 01 04 25 16 28 90 01 04 72 90 01 04 72 90 01 04 6f 90 01 04 28 90 01 04 a2 6f 90 01 04 74 90 01 04 0a 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}