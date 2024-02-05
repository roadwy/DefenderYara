
rule Trojan_BAT_AgentTesla_MBAW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 04 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 2d 00 35 00 41 00 2d 00 39 00 5b 00 7e 00 2d 00 5b 00 33 00 7e 00 7e 00 7e 00 2d 00 5b 00 34 00 7e 00 7e 00 7e 00 2d 00 46 00 46 00 2d 00 46 00 46 00 7e 00 7e 00 2d 00 42 00 38 00 7e 00 7e 00 } //04 00 
		$a_01_1 = {31 00 46 00 2d 00 31 00 45 00 2d 00 32 00 5b 00 2d 00 44 00 41 00 7e 00 7e 00 7e 00 2d 00 37 00 33 00 2d 00 33 00 34 00 7e 00 7e 00 2d 00 5b 00 41 00 2d 00 } //01 00 
		$a_01_2 = {52 65 70 6c 61 63 65 } //01 00 
		$a_01_3 = {53 70 6c 69 74 } //00 00 
	condition:
		any of ($a_*)
 
}