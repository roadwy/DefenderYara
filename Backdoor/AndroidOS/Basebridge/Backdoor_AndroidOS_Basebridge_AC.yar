
rule Backdoor_AndroidOS_Basebridge_AC{
	meta:
		description = "Backdoor:AndroidOS/Basebridge.AC,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 61 5f 42 53 65 72 76 65 72 33 } //02 00 
		$a_00_1 = {4c 63 6f 6d 2f 73 65 63 2f 61 6e 64 72 6f 69 64 2f 62 72 69 64 67 65 2f 42 72 69 64 67 65 50 72 6f 76 69 64 65 72 } //02 00 
		$a_00_2 = {5f 73 6d 73 5f 73 63 72 65 65 6e 5f 66 69 6e 69 73 68 5f 62 6f 64 79 5f 63 68 61 72 67 65 } //02 00 
		$a_00_3 = {6a 6b 5f 62 65 53 65 6e 64 53 6d 73 42 61 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}