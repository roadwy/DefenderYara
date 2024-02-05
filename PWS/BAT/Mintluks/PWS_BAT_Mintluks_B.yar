
rule PWS_BAT_Mintluks_B{
	meta:
		description = "PWS:BAT/Mintluks.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 43 6f 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00 
		$a_01_1 = {2e 00 74 00 6d 00 70 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_2 = {44 65 66 6c 61 74 65 5f 44 } //01 00 
		$a_01_3 = {44 65 6c 4d 65 } //00 00 
	condition:
		any of ($a_*)
 
}