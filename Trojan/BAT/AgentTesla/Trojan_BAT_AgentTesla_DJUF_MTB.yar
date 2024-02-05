
rule Trojan_BAT_AgentTesla_DJUF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DJUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 16 f4 00 00 0c 2b 13 00 72 90 01 03 70 07 08 28 90 01 03 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 90 00 } //01 00 
		$a_01_1 = {4f 00 76 00 65 00 72 00 73 00 69 00 6b 00 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}