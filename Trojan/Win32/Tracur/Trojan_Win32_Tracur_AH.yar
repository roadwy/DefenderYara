
rule Trojan_Win32_Tracur_AH{
	meta:
		description = "Trojan:Win32/Tracur.AH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 2e 4a 50 47 74 90 01 01 3d 2e 6a 70 67 74 90 01 01 3d 2e 65 78 65 74 90 01 01 3d 2e 74 6d 70 74 90 01 01 3d 2e 45 58 45 74 90 01 01 3d 2e 54 4d 50 90 00 } //1
		$a_03_1 = {8b 45 08 89 c7 89 d3 90 90 31 1f 90 90 83 c7 04 50 58 e2 f5 90 00 } //1
		$a_01_2 = {80 30 5a 40 e2 fa 5b 8b 45 08 8b 08 81 f9 14 e2 a4 fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}