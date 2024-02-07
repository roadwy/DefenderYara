
rule Trojan_Win32_SelfDel_BC_MTB{
	meta:
		description = "Trojan:Win32/SelfDel.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c3 81 f0 90 01 04 83 c0 90 01 01 81 f0 90 01 04 2b 05 90 01 04 83 c0 90 01 01 33 c3 89 05 90 00 } //01 00 
		$a_03_1 = {33 c8 83 e9 90 01 01 81 f1 90 01 04 03 0d 90 01 04 89 0d 90 00 } //01 00 
		$a_01_2 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00  QueryPerformanceCounter
	condition:
		any of ($a_*)
 
}