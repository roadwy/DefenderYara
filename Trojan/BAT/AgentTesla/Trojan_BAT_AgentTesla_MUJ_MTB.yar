
rule Trojan_BAT_AgentTesla_MUJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MUJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 28 90 01 04 10 00 90 00 } //0a 00 
		$a_02_1 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 61 b4 28 90 01 04 fe 0b 00 00 90 00 } //0a 00 
		$a_02_2 = {02 03 05 03 8e 69 5d 91 05 04 03 8e 69 5d d6 04 5f 90 02 28 61 b4 28 90 01 04 fe 0b 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}