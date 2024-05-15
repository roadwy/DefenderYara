
rule Trojan_BAT_Rozena_N_MTB{
	meta:
		description = "Trojan:BAT/Rozena.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 16 06 09 16 12 02 28 90 01 01 00 00 06 0b 16 90 00 } //01 00 
		$a_01_1 = {53 70 6f 74 69 66 79 73 2e 65 78 65 } //00 00  Spotifys.exe
	condition:
		any of ($a_*)
 
}