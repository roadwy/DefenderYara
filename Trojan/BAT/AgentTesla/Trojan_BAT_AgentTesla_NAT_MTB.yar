
rule Trojan_BAT_AgentTesla_NAT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 2e 00 00 0a 02 72 90 01 01 00 00 70 28 90 01 01 00 00 06 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 19 2d 03 26 de 06 0a 2b fb 90 00 } //01 00 
		$a_01_1 = {43 75 74 73 6f 67 67 77 67 } //00 00  Cutsoggwg
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAT_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 6f 90 01 03 0a 0c 06 08 28 90 01 03 0a 07 59 28 90 01 03 0a 8c 90 01 03 01 28 90 01 03 0a 0a 11 04 17 58 13 04 11 04 09 6f 90 01 03 0a 3f 90 00 } //01 00 
		$a_01_1 = {32 61 62 39 39 63 66 2d 38 65 33 35 2d 34 35 33 65 2d 38 38 64 36 2d 34 33 64 31 36 30 30 31 65 64 35 } //00 00  2ab99cf-8e35-453e-88d6-43d16001ed5
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NAT_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 82 0f 00 70 20 90 01 03 21 38 90 01 03 00 72 90 01 03 70 20 90 01 03 54 38 90 01 03 00 72 90 01 03 70 61 38 90 01 03 00 72 90 01 03 70 20 90 01 03 75 38 90 01 03 00 72 90 01 03 70 40 90 01 03 00 38 90 01 03 00 72 90 01 03 70 90 00 } //01 00 
		$a_01_1 = {4a 00 49 00 54 00 53 00 74 00 61 00 72 00 74 00 65 00 72 00 } //00 00  JITStarter
	condition:
		any of ($a_*)
 
}