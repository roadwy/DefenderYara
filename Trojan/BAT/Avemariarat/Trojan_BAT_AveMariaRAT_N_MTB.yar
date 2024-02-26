
rule Trojan_BAT_AveMariaRAT_N_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 95 02 3c c9 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 47 00 00 00 16 00 00 00 58 00 00 00 93 } //01 00 
		$a_01_1 = {67 65 74 5f 49 73 41 74 74 61 63 68 65 64 } //01 00  get_IsAttached
		$a_01_2 = {50 61 72 61 6d 65 74 65 72 69 7a 65 64 54 68 72 65 61 64 53 74 61 72 74 } //00 00  ParameterizedThreadStart
	condition:
		any of ($a_*)
 
}