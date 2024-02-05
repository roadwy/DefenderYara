
rule Backdoor_BAT_Plupay_A_bit{
	meta:
		description = "Backdoor:BAT/Plupay.A!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 00 6e 00 69 00 6d 00 61 00 6c 00 63 00 6f 00 6c 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 73 00 74 00 5f 00 6e 00 2e 00 70 00 68 00 70 00 } //01 00 
		$a_01_1 = {70 00 6c 00 75 00 67 00 61 00 6e 00 64 00 70 00 6c 00 61 00 79 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}