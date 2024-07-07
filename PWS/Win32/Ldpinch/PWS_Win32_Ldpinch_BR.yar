
rule PWS_Win32_Ldpinch_BR{
	meta:
		description = "PWS:Win32/Ldpinch.BR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {be 00 00 40 00 8b 45 24 66 33 c0 66 81 38 4d 5a 74 07 2d 00 00 01 00 eb } //1
		$a_03_1 = {64 8b 40 30 0f b6 40 02 85 c0 75 90 01 01 e8 00 00 00 00 90 00 } //1
		$a_01_2 = {33 c0 64 8b 40 18 8b 40 30 c7 40 08 00 00 40 00 } //1
		$a_03_3 = {0f 31 8b d8 68 f4 01 00 00 e8 90 01 03 00 0f 31 2b c3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}