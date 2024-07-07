
rule Trojan_Win32_Gepys_A{
	meta:
		description = "Trojan:Win32/Gepys.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 40 11 49 8b 0d 90 01 04 c6 41 12 6e 8b 15 90 01 04 c6 42 13 74 a1 90 00 } //10
		$a_03_1 = {2e 74 6d 70 00 47 45 54 90 02 07 50 4f 53 54 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Gepys_A_2{
	meta:
		description = "Trojan:Win32/Gepys.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {83 c8 ff eb 1a 0f b6 11 33 d0 81 e2 ff 00 00 00 c1 e8 08 33 04 95 90 01 04 41 ff 4c 24 04 83 7c 24 04 00 7f df 90 00 } //1
		$a_03_1 = {3d d5 c6 dd c3 74 90 01 01 3d 10 5f e3 b4 74 90 01 01 3d d1 ed 7a 26 90 00 } //1
		$a_03_2 = {3d 7e 23 ae 88 74 90 01 01 3d 53 4d a8 66 74 90 01 01 3d bc b4 b8 ee 90 00 } //1
		$a_03_3 = {bb 20 37 ef c6 c7 45 fc 20 00 00 00 ff 75 0c 53 57 6a 0b 59 e8 90 01 04 ff 75 0c 81 c3 47 86 c8 61 90 00 } //1
		$a_03_4 = {8b 45 fc 8b 08 31 0e 8b 40 04 31 46 04 90 01 01 79 cc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}