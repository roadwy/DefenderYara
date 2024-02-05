
rule Trojan_BAT_AgentTesla_ABP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {95 6e 31 03 16 2b 01 17 17 59 7e 2c 00 00 04 20 04 0a 00 00 95 5f 7e 2c 00 00 04 20 88 08 00 00 95 61 58 81 07 00 00 01 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_ABP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {11 05 11 0a 8f 13 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } //01 00 
		$a_01_1 = {36 00 37 00 2e 00 30 00 2e 00 33 00 33 00 39 00 36 00 2e 00 38 00 37 00 } //00 00 
	condition:
		any of ($a_*)
 
}