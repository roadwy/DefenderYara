
rule Backdoor_BAT_Quasarat_A_bit{
	meta:
		description = "Backdoor:BAT/Quasarat.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 64 65 73 63 72 65 76 65 61 62 63 00 } //01 00 
		$a_01_1 = {5c 52 65 6d 6f 74 65 5c 51 75 61 73 61 72 52 41 54 2d 6d 61 73 74 65 72 } //01 00 
		$a_01_2 = {00 64 65 73 63 72 65 76 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}