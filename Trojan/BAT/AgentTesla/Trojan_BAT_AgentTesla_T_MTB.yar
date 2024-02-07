
rule Trojan_BAT_AgentTesla_T_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 0a 02 06 8f 90 01 03 01 25 71 90 01 03 01 7e 90 01 03 04 03 1f 10 5d 91 61 d2 81 90 01 03 01 02 06 91 0b 2b 00 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_T_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.T!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 41 41 51 71 56 54 } //01 00  MAAQqVT
		$a_01_1 = {3d 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c 2c } //00 00  =,,,,,,,,,,,,,,,,,,
	condition:
		any of ($a_*)
 
}