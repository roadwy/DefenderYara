
rule Trojan_BAT_AgentTesla_OXBL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OXBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0b 06 8e 69 17 59 0c 2b 17 07 06 08 8f 90 01 04 28 90 01 04 28 90 01 04 0b 08 17 59 0c 08 15 fe 02 0d 09 2d e1 07 13 04 11 04 2a 90 00 } //02 00 
		$a_80_1 = {47 65 74 54 79 70 65 } //GetType  02 00 
		$a_80_2 = {47 65 74 4d 65 74 68 6f 64 } //GetMethod  02 00 
		$a_80_3 = {52 65 70 6c 61 63 65 } //Replace  02 00 
		$a_80_4 = {53 75 62 73 74 72 69 6e 67 } //Substring  00 00 
	condition:
		any of ($a_*)
 
}