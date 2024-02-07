
rule Trojan_BAT_DarkNeuron_C_dha{
	meta:
		description = "Trojan:BAT/DarkNeuron.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 04 00 00 14 00 "
		
	strings :
		$a_01_0 = {42 53 4a 42 } //01 00  BSJB
		$a_00_1 = {eb 07 3d 15 12 31 01 12 34 08 0e 12 81 8d 1d 05 12 81 31 1d 12 81 21 1d 12 81 21 1d 12 81 21 08 1d 12 81 21 1d 12 81 21 1d 12 } //01 00 
		$a_00_2 = {81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 } //01 00 
		$a_00_3 = {1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 21 1d 12 81 } //00 00 
	condition:
		any of ($a_*)
 
}