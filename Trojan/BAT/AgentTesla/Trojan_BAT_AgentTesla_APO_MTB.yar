
rule Trojan_BAT_AgentTesla_APO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.APO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {06 03 08 03 90 01 05 5d 17 d6 90 01 05 da 0d 06 09 90 01 0f 0a 00 08 17 d6 0c 08 07 fe 02 16 fe 01 13 04 11 04 2d c2 90 00 } //0a 00 
		$a_02_1 = {0a 03 08 03 90 01 05 5d 17 d6 90 01 05 da 0d 06 09 90 01 0f 0a 08 17 d6 0c 08 07 fe 02 16 fe 01 13 04 11 04 2d c4 90 00 } //02 00 
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  02 00 
		$a_80_3 = {47 65 74 54 79 70 65 } //GetType  00 00 
	condition:
		any of ($a_*)
 
}