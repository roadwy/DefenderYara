
rule Trojan_BAT_AgentTesla_MLK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {25 16 07 a2 25 17 19 8d 90 01 02 00 01 25 16 7e 90 01 02 00 04 a2 25 17 7e 90 01 02 00 04 a2 25 18 72 90 01 02 00 70 a2 a2 6f 90 01 02 00 0a 26 90 00 } //01 00 
		$a_80_1 = {43 4d 53 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //CMS.Resources.resources  01 00 
		$a_80_2 = {43 4d 53 2e 48 65 74 74 2e 72 65 73 6f 75 72 63 65 73 } //CMS.Hett.resources  00 00 
	condition:
		any of ($a_*)
 
}