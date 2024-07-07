
rule Trojan_Win32_Zbot_dwuq_MTB{
	meta:
		description = "Trojan:Win32/Zbot.dwuq!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b f2 d1 ee 57 8b f9 74 2e 53 8d 1c 3e 2b d6 8b cb e8 90 01 04 8b d6 8b cf e8 90 01 04 33 c0 85 f6 74 11 90 00 } //10
		$a_02_1 = {8b f8 8b 45 f4 8b cf 2b c7 be 90 01 04 8a 14 08 88 11 41 4e 75 f7 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}