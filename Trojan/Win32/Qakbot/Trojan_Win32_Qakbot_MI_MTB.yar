
rule Trojan_Win32_Qakbot_MI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 c8 3b 45 cc 73 90 01 01 6a 90 01 01 e8 90 01 04 8b 55 f4 03 55 c8 8b 45 ec 03 45 c4 8b 4d d4 e8 90 01 04 8b 45 d4 01 45 c4 8b 45 d4 01 45 c8 8b 45 d0 01 45 c8 eb 90 01 01 8b 45 e8 90 00 } //10
		$a_03_1 = {03 d8 8b 45 ec 31 18 6a 00 e8 90 01 04 8b 55 e8 83 c2 04 03 c2 89 45 e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}