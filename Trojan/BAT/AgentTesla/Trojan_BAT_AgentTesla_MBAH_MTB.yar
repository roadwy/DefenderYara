
rule Trojan_BAT_AgentTesla_MBAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 00 5a 00 53 00 69 00 2f 00 50 00 6a 00 68 00 31 00 5a 00 2f 00 39 00 35 00 6b 00 52 00 6d 00 61 00 65 00 41 00 56 00 75 00 6b 00 54 00 55 00 66 00 63 00 6e 00 35 00 4c 00 63 00 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}