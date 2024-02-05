
rule Trojan_BAT_AgentTesla_CAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 16 18 58 e0 91 20 c7 00 00 00 2e 03 16 2b 01 17 17 59 7e 11 00 00 04 20 db 00 00 00 95 5f 7e 11 00 00 04 20 7f 02 00 00 95 61 58 80 20 00 00 04 } //00 00 
	condition:
		any of ($a_*)
 
}