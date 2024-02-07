
rule Backdoor_BAT_Lyceum_JFV_MTB{
	meta:
		description = "Backdoor:BAT/Lyceum.JFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 08 11 04 8f 4e 00 00 01 72 de 09 00 70 28 90 01 03 0a 6f 90 01 03 0a 26 11 04 17 58 13 04 11 04 08 8e 69 32 da 90 00 } //01 00 
		$a_01_1 = {63 00 79 00 62 00 65 00 72 00 63 00 6c 00 75 00 62 00 2e 00 6f 00 6e 00 65 00 } //00 00  cyberclub.one
	condition:
		any of ($a_*)
 
}