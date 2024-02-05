
rule Trojan_BAT_AgentTesla_ASCR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 72 90 01 01 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 07 07 6f 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 73 90 01 01 00 00 0a 0d 09 08 17 73 90 01 01 00 00 0a 13 04 11 04 06 16 06 8e 69 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 13 05 dd 90 00 } //01 00 
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}