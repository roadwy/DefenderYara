
rule TrojanDropper_BAT_VB_AE{
	meta:
		description = "TrojanDropper:BAT/VB.AE,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {4d 61 72 74 69 6e 53 74 65 65 6c 31 2e 4d 79 } //05 00 
		$a_01_1 = {70 72 65 77 72 69 74 65 2e 43 68 61 6e 67 6c 69 6e 67 73 2e 64 6c 6c } //07 00 
		$a_01_2 = {43 00 68 00 61 00 6e 00 67 00 6c 00 69 00 6e 00 67 00 73 00 2e 00 4d 00 6c 00 69 00 66 00 65 00 64 00 2c 00 20 00 43 00 68 00 61 00 6e 00 67 00 6c 00 69 00 6e 00 67 00 73 00 } //00 00 
		$a_00_3 = {5d 04 00 00 0c b6 } //02 80 
	condition:
		any of ($a_*)
 
}