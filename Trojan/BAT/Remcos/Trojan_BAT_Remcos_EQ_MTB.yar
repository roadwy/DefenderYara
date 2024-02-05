
rule Trojan_BAT_Remcos_EQ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 69 73 6b 20 44 72 69 6c 6c } //01 00 
		$a_03_1 = {63 6f 73 74 75 72 61 2e 90 02 0f 2e 64 6c 6c 90 00 } //01 00 
		$a_81_2 = {2e 63 6f 6d 70 72 65 73 73 65 64 } //01 00 
		$a_81_3 = {41 73 73 65 6d 62 6c 79 4c 6f 61 64 65 72 } //01 00 
		$a_81_4 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00 
		$a_81_5 = {4c 6f 61 64 53 74 72 65 61 6d } //01 00 
		$a_81_6 = {43 6f 6e 73 6f 6c 65 41 70 70 } //00 00 
	condition:
		any of ($a_*)
 
}