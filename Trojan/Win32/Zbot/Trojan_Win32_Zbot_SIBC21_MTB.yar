
rule Trojan_Win32_Zbot_SIBC21_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBC21!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5a 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 90 01 01 75 90 01 01 31 c9 83 ea 90 01 01 47 39 f8 75 90 00 } //1
		$a_02_1 = {8b 5d 00 83 eb 90 01 01 be 90 01 04 29 f3 89 1c 24 57 be 90 01 04 01 de b9 90 01 04 f3 a4 be 90 01 04 01 de b9 90 01 04 f3 a4 5f be 90 01 04 85 f6 74 90 01 01 ba 90 01 04 01 fa b8 90 01 04 01 f8 89 c7 89 44 24 90 01 01 be 90 01 04 01 c6 80 38 90 01 01 75 90 01 01 8a 0a 88 08 42 40 39 c6 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}