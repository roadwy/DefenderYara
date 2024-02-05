
rule Trojan_BAT_AgentTesla_AEM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {25 16 19 8d 90 01 03 01 25 16 7e 90 01 03 04 a2 25 17 7e 90 01 03 04 a2 25 18 72 90 01 03 70 a2 a2 6f 90 01 03 0a 26 20 00 08 00 00 0a 90 00 } //0a 00 
		$a_02_1 = {09 11 04 9a 13 05 11 05 28 90 01 03 0a 23 00 00 00 00 00 80 73 40 59 28 90 01 03 0a b7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}