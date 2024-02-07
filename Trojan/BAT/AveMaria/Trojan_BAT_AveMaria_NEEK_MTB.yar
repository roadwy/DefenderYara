
rule Trojan_BAT_AveMaria_NEEK_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {39 32 38 38 37 35 35 34 2d 30 32 62 66 2d 34 34 64 30 2d 61 36 66 34 2d 36 61 30 65 66 33 35 66 37 39 39 38 } //02 00  92887554-02bf-44d0-a6f4-6a0ef35f7998
		$a_01_1 = {43 53 45 35 33 35 2e 6b 65 79 6d 6e 2e 72 65 73 6f 75 72 63 65 73 } //02 00  CSE535.keymn.resources
		$a_01_2 = {43 53 45 35 33 35 2e 46 72 76 61 72 69 62 6c 65 2e 72 65 73 6f 75 72 63 65 73 } //02 00  CSE535.Frvarible.resources
		$a_01_3 = {52 6f 6d 70 20 32 30 32 33 } //01 00  Romp 2023
		$a_01_4 = {6c 65 76 65 6e 73 68 74 65 69 6e 31 5f 4c 6f 61 64 } //00 00  levenshtein1_Load
	condition:
		any of ($a_*)
 
}