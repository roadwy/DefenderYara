
rule Trojan_Win32_Vidar_HT_MTB{
	meta:
		description = "Trojan:Win32/Vidar.HT!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 4c 24 20 8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d 34 28 35 02 8c 07 00 00 c7 05 e0 87 34 02 00 00 00 00 89 4c 24 10 } //1
		$a_01_1 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}