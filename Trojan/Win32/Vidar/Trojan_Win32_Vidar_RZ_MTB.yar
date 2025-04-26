
rule Trojan_Win32_Vidar_RZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 37 83 c4 0c 34 74 8b cb 04 59 88 04 37 6a 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_RZ_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 4c 24 28 8b d0 c1 ea 05 03 54 24 20 03 c5 33 d1 33 d0 2b fa } //1
		$a_01_1 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}