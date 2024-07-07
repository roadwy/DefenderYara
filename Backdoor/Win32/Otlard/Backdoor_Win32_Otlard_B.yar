
rule Backdoor_Win32_Otlard_B{
	meta:
		description = "Backdoor:Win32/Otlard.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 70 04 ff 70 0c e8 90 01 04 39 75 0c 89 77 58 0f 94 c0 90 00 } //2
		$a_03_1 = {74 07 b8 01 00 00 00 eb 1d 68 90 01 04 8b 4d 08 51 ff 15 90 00 } //2
		$a_01_2 = {75 0e ff 45 fc 8b 45 fc 83 c6 08 3b 45 f0 72 b3 ff 75 f4 } //1
		$a_01_3 = {2f 62 6f 6f 74 73 74 72 61 70 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}