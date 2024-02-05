
rule Backdoor_MacOS_Mettle_A_MTB{
	meta:
		description = "Backdoor:MacOS/Mettle.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 70 72 6f 63 65 73 73 2e 63 } //01 00 
		$a_00_1 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 65 78 74 65 6e 73 69 6f 6e 73 2f 73 6e 69 66 66 65 72 2f 73 6e 69 66 66 65 72 2e 63 } //01 00 
		$a_00_2 = {2f 6d 65 74 74 6c 65 2f 6d 65 74 74 6c 65 2f 73 72 63 2f 74 6c 76 2e 63 } //01 00 
		$a_00_3 = {5f 65 78 74 65 6e 73 69 6f 6e 5f 6c 6f 67 5f 74 6f 5f 6d 65 74 74 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}