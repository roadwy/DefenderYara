
rule Trojan_Win32_Cinmus_L{
	meta:
		description = "Trojan:Win32/Cinmus.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 50 72 6f 00 } //01 00 
		$a_01_1 = {44 6f 53 53 53 65 74 75 70 00 } //01 00  潄卓敓畴p
		$a_01_2 = {74 03 75 01 e8 } //00 00 
	condition:
		any of ($a_*)
 
}