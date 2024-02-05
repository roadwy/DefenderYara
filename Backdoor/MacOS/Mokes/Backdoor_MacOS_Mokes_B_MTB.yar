
rule Backdoor_MacOS_Mokes_B_MTB{
	meta:
		description = "Backdoor:MacOS/Mokes.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 6f 72 65 75 73 65 72 64 } //01 00 
		$a_00_1 = {6a 69 6b 65 6e 69 63 6b 31 32 61 6e 64 36 37 2e 63 6f 6d } //01 00 
		$a_00_2 = {2f 00 6b 00 65 00 79 00 73 00 2f 00 62 00 6f 00 74 00 } //01 00 
		$a_00_3 = {2f 63 63 58 58 58 58 58 58 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}