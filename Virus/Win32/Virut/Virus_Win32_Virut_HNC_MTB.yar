
rule Virus_Win32_Virut_HNC_MTB{
	meta:
		description = "Virus:Win32/Virut.HNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {77 62 00 00 72 62 00 00 5c 74 65 6d 70 32 2e 65 78 65 00 00 00 00 00 00 5c 74 65 6d 70 31 2e 65 78 65 00 00 00 } //2
		$a_01_1 = {8b 74 24 18 8b 44 24 14 d1 e8 46 89 44 24 14 83 fe 1a 89 74 24 18 } //1
		$a_01_2 = {f3 a4 eb 06 c7 06 00 00 00 00 8b 54 24 1c 8b 44 24 18 8b 74 24 10 33 c9 66 8b 4a 04 40 83 c6 0e 3b c1 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}