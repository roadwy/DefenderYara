
rule Trojan_BAT_AgentTesla_MI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {fe 0c 02 00 20 90 01 04 fe 01 39 27 00 00 00 20 23 00 00 00 28 90 01 18 20 02 00 00 00 fe 0e 02 00 90 00 } //01 00 
		$a_01_1 = {2f 00 6f 00 70 00 74 00 69 00 6d 00 69 00 7a 00 65 00 2b 00 20 00 2f 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 3a 00 58 00 38 00 36 00 20 00 2f 00 74 00 61 00 72 00 67 00 65 00 74 00 3a 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}