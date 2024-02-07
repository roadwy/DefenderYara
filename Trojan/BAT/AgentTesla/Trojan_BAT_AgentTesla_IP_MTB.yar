
rule Trojan_BAT_AgentTesla_IP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {11 07 11 0a 03 11 0a 91 11 03 61 d2 9c 20 16 00 00 00 38 e2 fe ff ff } //01 00 
		$a_81_1 = {31 35 36 32 30 63 30 33 2d 31 35 34 37 2d 34 66 65 38 2d 62 34 62 35 2d 38 32 35 34 61 61 35 65 31 35 33 63 } //01 00  15620c03-1547-4fe8-b4b5-8254aa5e153c
		$a_81_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}