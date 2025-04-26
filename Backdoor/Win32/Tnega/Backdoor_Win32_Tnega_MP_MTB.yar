
rule Backdoor_Win32_Tnega_MP_MTB{
	meta:
		description = "Backdoor:Win32/Tnega.MP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 59 ba d3 88 3f 49 0d ec 32 1e } //1
		$a_01_1 = {8b 3f d3 e8 66 0f a4 f8 fa 66 35 e7 2d 8b 44 25 00 81 c5 04 00 00 00 66 85 fd 33 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}