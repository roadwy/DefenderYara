
rule Trojan_Win32_Qakbot_EY_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 c4 03 45 a4 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 ?? ?? ?? ?? 8b d8 03 5d a0 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 89 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_EY_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EY!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c2 0f b6 cb 2b c8 83 c1 b4 03 f9 8b 4c 24 0c 8b 01 05 88 7f 03 01 89 01 83 c1 04 } //10
		$a_01_1 = {8a ca 02 4c 24 10 b0 f0 02 c9 2a c1 8b ce 02 d8 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}