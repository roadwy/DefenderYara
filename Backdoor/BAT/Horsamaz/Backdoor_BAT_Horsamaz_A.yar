
rule Backdoor_BAT_Horsamaz_A{
	meta:
		description = "Backdoor:BAT/Horsamaz.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 00 79 00 48 00 6f 00 72 00 73 00 65 00 49 00 73 00 41 00 6d 00 61 00 7a 00 69 00 6e 00 67 00 } //01 00  MyHorseIsAmazing
		$a_01_1 = {55 00 64 00 70 00 20 00 46 00 6c 00 6f 00 6f 00 64 00 20 00 41 00 63 00 74 00 69 00 76 00 65 00 2e 00 2e 00 2e 00 } //01 00  Udp Flood Active...
		$a_01_2 = {41 00 6c 00 6c 00 20 00 46 00 6c 00 6f 00 6f 00 64 00 73 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00 2e 00 2e 00 2e 00 } //01 00  All Floods Disabled...
		$a_01_3 = {72 00 65 00 67 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //01 00  regClient
		$a_01_4 = {54 00 61 00 73 00 6b 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 20 00 6b 00 69 00 6c 00 6c 00 65 00 64 00 20 00 61 00 6e 00 64 00 20 00 72 00 65 00 2d 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 2e 00 2e 00 2e 00 } //00 00  Task Manager killed and re-enabled...
	condition:
		any of ($a_*)
 
}