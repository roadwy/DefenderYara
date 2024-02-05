
rule PWS_Win32_Ldpinch_ZT{
	meta:
		description = "PWS:Win32/Ldpinch.ZT,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 71 2e 71 71 2e 63 6f 6d 2f 63 6e 32 2f 66 69 6e 64 70 73 77 } //01 00 
		$a_01_1 = {51 51 2e 65 78 65 } //01 00 
		$a_01_2 = {54 68 65 20 42 61 74 21 } //00 00 
	condition:
		any of ($a_*)
 
}