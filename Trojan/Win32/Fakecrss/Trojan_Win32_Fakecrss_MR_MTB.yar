
rule Trojan_Win32_Fakecrss_MR_MTB{
	meta:
		description = "Trojan:Win32/Fakecrss.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 00 8a 74 18 90 01 01 88 b5 90 01 04 8a d6 8a 8d 90 01 04 80 e2 90 01 01 80 e6 90 01 01 c0 e1 90 01 01 0a 4c 18 90 01 01 c0 e2 90 01 01 0a 14 18 c0 e6 90 01 01 0a 74 18 90 01 01 81 3d 90 01 06 88 8d 90 01 04 8b 8d 90 01 04 88 95 90 01 04 88 b5 90 01 04 75 90 00 } //1
		$a_02_1 = {88 14 0e 88 74 0e 90 01 01 83 c6 90 01 01 89 b5 90 01 04 88 04 0e 8d 8d 90 01 04 e8 90 01 04 03 9d 90 01 04 8b b5 90 01 04 3b 1f 0f 82 90 00 } //1
		$a_00_2 = {44 69 67 69 79 65 79 6f 20 64 6f 67 75 6c 61 77 6f 78 65 20 68 69 7a 6f } //1 Digiyeyo dogulawoxe hizo
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}