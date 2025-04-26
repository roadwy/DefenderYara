
rule Trojan_Win32_Qakbot_Z{
	meta:
		description = "Trojan:Win32/Qakbot.Z,SIGNATURE_TYPE_PEHSTR_EXT,ffffffc9 00 ffffffc9 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {c7 45 10 5a 00 00 00 33 d2 8b c6 f7 75 10 8a 04 0a 8b 55 fc 3a 04 16 74 11 46 3b f3 72 e9 } //100
		$a_01_2 = {33 d2 8b c7 f7 75 10 8a 04 0a 8b 55 fc 32 04 17 88 04 3b 47 83 ee 01 75 e7 8b 4d f8 eb b6 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=201
 
}