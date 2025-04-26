
rule Trojan_Win32_Qakbot_AS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 } //2
		$a_03_1 = {8b 55 a0 2b d0 4a 8b 45 d8 33 10 89 55 a0 6a 00 e8 [0-04] 8b d8 03 5d a0 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 8b 45 d8 89 18 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_Win32_Qakbot_AS_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 5f 1d 00 00 77 ?? 40 89 45 ?? 3b [0-02] 72 90 0a 20 00 85 c0 74 ?? ff 15 ?? ?? ?? ?? 8b 45 } //1
		$a_03_1 = {0f b6 04 39 33 f0 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 41 3b ca 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}