
rule Trojan_BAT_AgentTesla_MBBV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 2b 00 35 00 41 00 2b 00 39 00 7d 00 5c 00 2b 00 7d 00 33 00 5c 00 5c 00 5c 00 2b 00 7d 00 34 00 5c 00 5c 00 5c 00 2b 00 46 00 46 00 2b 00 46 00 46 00 5c 00 5c 00 2b 00 42 00 38 00 5c } //01 00 
		$a_01_1 = {36 00 39 00 2b 00 37 00 33 00 2b 00 32 00 7d 00 2b 00 37 00 7d 00 2b 00 37 00 32 00 2b 00 36 00 46 00 2b 00 36 00 37 00 2b 00 37 00 32 00 2b 00 36 00 31 00 2b 00 } //00 00  69+73+2}+7}+72+6F+67+72+61+
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_MBBV_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 11 04 07 11 04 9a 1f 10 28 90 01 03 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc 90 00 } //01 00 
		$a_01_1 = {20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 41 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 } //01 00             System.Activator       
		$a_01_2 = {20 00 43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 20 00 } //01 00   CreateInstance 
		$a_01_3 = {4d 00 61 00 6e 00 6e 00 69 00 6e 00 67 00 2e 00 50 00 61 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 } //00 00  Manning.Passenger
	condition:
		any of ($a_*)
 
}