
rule Trojan_Win32_TrickBot_PVD_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 4c 38 03 8a d1 c0 e2 06 0a 54 38 02 8a c1 24 f0 80 e1 fc c0 e0 02 83 c7 04 0a 44 24 18 c0 e1 04 0a 4c 24 13 } //2
		$a_02_1 = {6a 59 59 33 d2 8b c6 f7 f1 c7 04 24 90 01 04 8a 82 90 01 04 30 86 90 01 04 e8 90 01 04 c7 04 24 90 01 04 e8 90 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}