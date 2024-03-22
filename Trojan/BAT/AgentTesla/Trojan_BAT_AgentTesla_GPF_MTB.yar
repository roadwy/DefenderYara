
rule Trojan_BAT_AgentTesla_GPF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 11 10 8f 33 00 00 01 25 47 07 11 10 07 8e 69 5d 91 61 d2 52 00 11 10 17 58 13 10 11 10 06 8e 69 fe 04 13 } //00 00 
	condition:
		any of ($a_*)
 
}