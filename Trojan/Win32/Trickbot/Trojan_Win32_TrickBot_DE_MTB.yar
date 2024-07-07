
rule Trojan_Win32_TrickBot_DE_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a d1 02 d2 8a c5 c0 f8 04 02 d2 24 03 02 c2 88 45 } //1
		$a_03_1 = {8a d0 c0 fa 02 8a cd c0 e1 04 80 e2 0f 32 d1 8b 4d 90 01 01 c0 e0 06 02 45 90 01 01 88 55 90 01 01 66 8b 55 90 01 01 66 89 11 88 41 02 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}