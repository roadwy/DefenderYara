
rule Trojan_Win32_Ekstak_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {41 4a 41 58 20 44 48 54 4d 4c 20 54 72 61 63 6b 69 6e 67 } //AJAX DHTML Tracking  1
	condition:
		((#a_80_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ekstak_GZZ_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 7e 95 41 00 b1 f2 3d 00 00 ca 0a 00 6a d1 } //10
		$a_01_1 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 5f 64 42 00 92 c1 3e 00 00 ca 0a 00 ad d5 9e } //10
		$a_01_2 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 96 10 43 00 c9 6d 3f 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=10
 
}