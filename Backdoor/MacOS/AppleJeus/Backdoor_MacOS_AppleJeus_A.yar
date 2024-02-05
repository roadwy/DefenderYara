
rule Backdoor_MacOS_AppleJeus_A{
	meta:
		description = "Backdoor:MacOS/AppleJeus.A,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 6f 7a 26 57 69 65 3b 23 74 2f 36 54 21 32 79 } //01 00 
		$a_01_1 = {2d 2d 6a 65 75 73 0d 0a 43 6f 6e 74 65 6e 74 2d } //01 00 
		$a_00_2 = {2f 76 61 72 2f 7a 64 69 66 66 73 65 63 00 46 69 6c 65 20 6f 70 65 6e 20 66 61 69 6c 65 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}