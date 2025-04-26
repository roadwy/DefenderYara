
rule Trojan_Win32_Cinmus_L{
	meta:
		description = "Trojan:Win32/Cinmus.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 50 72 6f 00 } //1
		$a_01_1 = {44 6f 53 53 53 65 74 75 70 00 } //1 潄卓敓畴p
		$a_01_2 = {74 03 75 01 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}