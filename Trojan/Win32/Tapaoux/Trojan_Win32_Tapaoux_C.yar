
rule Trojan_Win32_Tapaoux_C{
	meta:
		description = "Trojan:Win32/Tapaoux.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 73 25 73 25 } //1 exe.s%s%
		$a_01_1 = {4c 4d 54 48 6c 6f 72 74 6e 6f 43 2a 2a 2a 20 2d 2d 21 3c } //1 LMTHlortnoC*** --!<
		$a_00_2 = {80 7c 24 1b 44 0f 84 40 01 00 00 6a 01 83 c7 04 6a 00 57 56 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}