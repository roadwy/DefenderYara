
rule Trojan_Win32_Zbot_RC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 0b 42 51 00 8b 0d 90 01 04 bb 90 01 04 30 03 43 49 85 c9 75 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zbot_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 6b fa 03 00 01 85 90 01 04 8b 85 90 01 04 8a 0c 30 a1 90 01 04 88 0c 30 46 8b 0d 90 01 04 3b f1 72 90 00 } //1
		$a_00_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 3b 43 3b de 7c e7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Zbot_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {98 6c 00 8b c6 05 90 01 01 98 6c 00 ec c6 05 90 01 01 98 6c 00 83 c6 05 90 01 01 98 6c 00 c4 c6 05 90 01 01 98 6c 00 f0 c6 05 90 01 01 98 6c 00 b8 c6 05 90 01 01 98 6c 00 00 c6 05 90 01 01 98 6c 00 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}