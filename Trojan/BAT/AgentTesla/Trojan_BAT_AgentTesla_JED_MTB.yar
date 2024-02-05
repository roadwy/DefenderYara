
rule Trojan_BAT_AgentTesla_JED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {73 22 00 00 0a 0a 16 0b 2b 24 00 06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 00 07 17 58 0b 07 02 6f 90 01 03 0a fe 04 0c 08 2d cf 06 6f 90 01 03 0a 0d 2b 00 09 2a 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00 
		$a_81_2 = {54 6f 53 74 72 69 6e 67 } //01 00 
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}