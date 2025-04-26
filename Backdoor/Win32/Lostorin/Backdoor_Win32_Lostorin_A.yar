
rule Backdoor_Win32_Lostorin_A{
	meta:
		description = "Backdoor:Win32/Lostorin.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 96 00 00 00 73 04 6a 64 ff d3 ff d7 } //1
		$a_01_1 = {75 38 81 7e 04 02 12 00 00 74 22 8b 4e 08 } //1
		$a_01_2 = {c7 03 78 56 34 12 c7 43 04 08 00 00 00 c7 43 08 14 00 00 00 c7 43 0c 01 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}