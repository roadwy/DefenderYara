
rule Backdoor_AndroidOS_Luckycat_A{
	meta:
		description = "Backdoor:AndroidOS/Luckycat.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 63 72 65 61 74 65 20 73 6f 63 6b 65 74 20 6f 6b 21 } //01 00 
		$a_01_1 = {67 72 65 65 6e 66 75 6e 73 2e 33 33 32 32 2e 6f 72 67 } //01 00 
		$a_01_2 = {4e 65 74 77 6f 72 6b 50 49 4e } //01 00 
		$a_01_3 = {73 6f 63 6b 65 20 63 6c 6f 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}