
rule Trojan_Win32_Qakbot_ZX_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 59 8b 4d f8 3b 0d 90 01 04 72 02 eb 4c 8b 45 f8 33 d2 b9 90 01 02 00 00 f7 f1 85 d2 75 0e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_ZX_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.ZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 89 45 f4 8b 0d 90 01 04 03 4d fc 89 0d 90 01 04 8b 55 f4 89 55 e8 8b 45 e8 50 68 90 01 03 00 e8 90 01 04 83 c4 08 8b 4d f0 8b 55 fc 8d 84 0a 90 01 04 89 45 ec 8b 0d 90 01 04 89 0d 90 01 04 8b 55 ec 89 15 90 01 04 a1 90 01 04 a3 90 01 04 e8 90 01 04 8b 4d fc 83 c1 04 89 4d fc 8b 55 fc 3b 15 90 01 04 72 02 eb 0d b8 90 01 01 00 00 00 85 c0 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}