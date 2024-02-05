
rule PWS_BAT_Crasarm_A{
	meta:
		description = "PWS:BAT/Crasarm.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 65 74 4d 53 4e 37 35 50 61 73 73 77 6f 72 64 73 00 } //01 00 
		$a_01_1 = {53 6d 61 72 74 53 74 65 61 6c 65 72 20 43 72 61 63 6b 65 64 } //01 00 
		$a_01_2 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 5f 00 76 00 61 00 6c 00 75 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}