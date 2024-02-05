
rule Trojan_BAT_AgentTesla_KAAJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KAAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {fe 0c 01 00 fe 0c 02 00 8f 43 00 00 01 25 47 fe 0c 01 00 fe 0c 07 00 91 fe 0c 00 00 20 04 00 00 00 58 4a 61 d2 61 d2 52 20 11 00 00 00 fe 0e 0a 00 } //0a 00 
		$a_01_1 = {fe 0c 01 00 fe 0c 01 00 8e 69 20 01 00 00 00 63 8f 43 00 00 01 25 47 fe 0c 00 00 20 04 00 00 00 58 4a d2 61 d2 52 20 19 00 00 00 fe 0e 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}