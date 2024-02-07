
rule Trojan_BAT_AgentTesla_AMK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 0a 03 0b 06 8e 69 0c 16 0d 2b 14 07 09 07 09 91 06 09 08 5d 91 28 90 01 03 06 9c 09 17 58 0d 09 07 8e 69 32 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_AMK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 69 6e 5c 44 65 62 75 67 5c 53 4c 4e 5c 48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 5c 6f 62 6a 5c 44 65 62 75 67 5c 48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 70 64 62 } //01 00  bin\Debug\SLN\HotelManagementSystem\obj\Debug\HotelManagementSystem.pdb
		$a_01_1 = {48 6f 74 65 6c 4d 61 6e 61 67 65 6d 65 6e 74 53 79 73 74 65 6d 2e 65 78 65 } //00 00  HotelManagementSystem.exe
	condition:
		any of ($a_*)
 
}