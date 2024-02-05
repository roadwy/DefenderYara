
rule Trojan_BAT_Dapato_MTB{
	meta:
		description = "Trojan:BAT/Dapato!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {fa 25 33 00 16 00 00 01 00 00 00 3d 00 00 00 07 00 00 00 12 } //01 00 
		$a_01_1 = {42 6f 75 6e 63 79 43 61 73 74 6c 65 2e 43 72 79 70 74 6f } //01 00 
		$a_01_2 = {4f 72 67 2e 42 6f 75 6e 63 79 43 61 73 74 6c 65 2e 42 63 70 67 2e 4f 70 65 6e 50 67 70 } //01 00 
		$a_01_3 = {67 65 74 5f 4f 53 56 65 72 73 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}