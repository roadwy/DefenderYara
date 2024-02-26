
rule Trojan_BAT_AgentTesla_PSYU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSYU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 72 30 15 00 70 6f 92 00 00 0a 75 01 00 00 1b 0b 72 38 15 00 70 0c 19 8d 36 00 00 01 25 16 } //00 00 
	condition:
		any of ($a_*)
 
}