
rule Trojan_Win32_Sopinar_A{
	meta:
		description = "Trojan:Win32/Sopinar.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 3d 03 00 00 00 33 c0 c6 05 11 00 00 00 04 40 c7 05 5b 00 00 00 } //10
		$a_03_1 = {83 04 24 02 c7 45 ?? 60 9c e8 03 c7 45 ?? 00 00 00 9d } //1
		$a_01_2 = {66 c7 45 fc eb f9 66 c7 45 f8 8b ff eb 0b } //1
		$a_00_3 = {2d 00 75 00 20 00 2d 00 71 00 20 00 2d 00 6e 00 20 00 22 00 25 00 73 00 22 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*10) >=11
 
}