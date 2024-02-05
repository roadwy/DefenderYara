
rule PWS_Win32_Ldpinch_CX{
	meta:
		description = "PWS:Win32/Ldpinch.CX,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 2d 68 65 2d 6f 2d 72 75 2e 63 2d 6f 2d 6d } //01 00 
		$a_01_1 = {2a 31 36 33 2a 2e 74 78 74 } //01 00 
		$a_01_2 = {2a 61 6c 69 6d 61 6d 61 2a 2e 74 78 74 } //01 00 
		$a_01_3 = {2a 61 6c 69 75 6e 69 6f 6e 2a 2e 74 78 74 } //01 00 
		$a_01_4 = {2a 62 61 69 64 75 2a 2e 74 78 74 } //01 00 
		$a_01_5 = {2a 67 6f 6f 67 6c 65 2a 2e 74 78 74 } //01 00 
		$a_01_6 = {2a 73 69 6e 61 2a 2e 74 78 74 } //01 00 
		$a_01_7 = {2a 73 6f 67 6f 75 2a 2e 74 78 74 } //01 00 
		$a_01_8 = {2a 73 6f 68 75 2a 2e 74 78 74 } //01 00 
		$a_01_9 = {2a 79 61 68 6f 6f 2a 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}