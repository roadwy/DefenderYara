
rule Worm_BAT_Remrochor_A{
	meta:
		description = "Worm:BAT/Remrochor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 68 72 6f 6d 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_1 = {61 6e 74 69 53 61 6e 64 62 6f 78 69 65 00 61 6e 74 69 41 6e 75 62 69 73 } //01 00 
		$a_01_2 = {53 70 72 65 61 64 00 47 65 74 44 65 63 72 79 70 74 65 64 44 61 74 61 } //00 00 
	condition:
		any of ($a_*)
 
}