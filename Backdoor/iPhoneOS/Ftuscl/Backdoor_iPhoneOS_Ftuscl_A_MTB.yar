
rule Backdoor_iPhoneOS_Ftuscl_A_MTB{
	meta:
		description = "Backdoor:iPhoneOS/Ftuscl.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 70 79 43 61 6c 6c 4d 61 6e 61 67 65 72 53 6e 61 70 73 68 6f 74 } //01 00 
		$a_00_1 = {76 61 72 2f 2e 6c 73 61 6c 63 6f 72 65 2f 73 68 61 72 65 73 2f } //01 00 
		$a_00_2 = {46 78 43 61 6c 6c } //01 00 
		$a_00_3 = {73 65 6e 64 43 6f 6d 6d 61 6e 64 54 6f 53 70 79 43 61 6c 6c 44 61 65 6d 6f 6e 3a 63 6d 64 49 6e 66 6f } //00 00 
	condition:
		any of ($a_*)
 
}