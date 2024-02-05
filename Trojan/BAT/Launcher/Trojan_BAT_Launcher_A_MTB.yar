
rule Trojan_BAT_Launcher_A_MTB{
	meta:
		description = "Trojan:BAT/Launcher.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 1d 00 00 0a 26 de 0c 28 1e 00 00 0a 28 1f 00 00 0a de 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Launcher_A_MTB_2{
	meta:
		description = "Trojan:BAT/Launcher.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 78 00 6e 00 6f 00 64 00 33 00 32 00 5c 00 78 00 6e 00 6f 00 64 00 33 00 32 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_1 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 } //00 00 
		$a_01_2 = {00 78 } //26 00 
	condition:
		any of ($a_*)
 
}