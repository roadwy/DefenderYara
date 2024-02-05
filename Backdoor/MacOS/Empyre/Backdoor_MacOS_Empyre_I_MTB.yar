
rule Backdoor_MacOS_Empyre_I_MTB{
	meta:
		description = "Backdoor:MacOS/Empyre.I!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 63 74 69 76 61 74 65 53 74 61 67 65 72 } //01 00 
		$a_01_1 = {74 65 6d 70 6c 61 74 65 44 79 6c 69 62 2e 63 } //01 00 
		$a_03_2 = {62 61 73 65 36 34 90 02 10 65 78 65 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}