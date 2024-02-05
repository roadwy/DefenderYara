
rule Trojan_BAT_AgentTesla_SB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {04 06 91 20 90 01 04 59 d2 9c 00 06 17 58 0a 06 7e 90 01 04 8e 69 fe 04 0b 07 2d d7 90 00 } //01 00 
		$a_80_1 = {6e 61 64 6a 6f 64 6f 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 } //nadjodo.duckdns.org  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_SB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {28 51 00 00 0a 02 d6 6c 0b 2b 0e 17 28 52 00 00 0a 00 28 53 00 00 0a 00 00 28 51 00 00 0a 6c 07 fe 04 0c 08 2d e5 } //03 00 
		$a_80_1 = {43 68 65 63 6b 46 69 6c 65 4c 6f 63 61 74 69 6f 6e } //CheckFileLocation  03 00 
		$a_80_2 = {41 64 64 54 6f 5f 4e 6f 6e 4b 65 79 } //AddTo_NonKey  03 00 
		$a_80_3 = {49 6e 66 6f 5f 47 72 61 62 5f 49 42 } //Info_Grab_IB  03 00 
		$a_80_4 = {57 65 62 5f 4e 65 77 41 64 64 72 65 73 73 } //Web_NewAddress  00 00 
	condition:
		any of ($a_*)
 
}