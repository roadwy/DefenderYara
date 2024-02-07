
rule Trojan_Win32_SelfDel_TC_MTB{
	meta:
		description = "Trojan:Win32/SelfDel.TC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 df 33 1d 90 01 04 81 c3 90 01 04 83 eb 07 33 1d 90 01 04 89 5d e0 90 00 } //01 00 
		$a_03_1 = {8b f0 81 c6 90 01 04 83 f6 0f 03 f3 83 ee 41 33 f7 89 35 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {51 75 65 72 79 50 65 72 66 6f 72 6d 61 6e 63 65 43 6f 75 6e 74 65 72 } //00 00  QueryPerformanceCounter
	condition:
		any of ($a_*)
 
}