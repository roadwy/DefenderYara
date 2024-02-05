
rule Trojan_BAT_AgentTesla_BNH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 00 07 17 58 0b 07 02 6f 90 01 03 0a fe 04 0c 08 2d 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_81_2 = {52 65 70 6c 61 63 65 } //01 00 
		$a_81_3 = {78 6f 72 65 64 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}