
rule Worm_BAT_Lime_A_bit{
	meta:
		description = "Worm:BAT/Lime.A!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 00 69 00 6d 00 65 00 5f 00 57 00 6f 00 72 00 6d 00 } //01 00 
		$a_01_1 = {4d 00 6f 00 64 00 75 00 6c 00 65 00 20 00 4e 00 65 00 72 00 76 00 6f 00 75 00 73 00 6e 00 65 00 73 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}