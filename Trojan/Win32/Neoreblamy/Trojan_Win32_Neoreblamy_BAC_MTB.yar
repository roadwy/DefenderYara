
rule Trojan_Win32_Neoreblamy_BAC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 45 fc 33 d2 f7 35 ?? ?? ?? 00 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ?? ff 59 59 8b 4d f4 03 4d f8 88 01 eb } //3
		$a_01_1 = {0f b6 45 fd 0f b6 4d fc 0b c1 89 45 ec 8a 45 ec 88 45 fb 8b 45 f0 d1 e0 89 45 f0 0f b6 45 fb 0b 45 f0 89 45 f0 eb } //3
		$a_01_2 = {0f b6 04 0a 33 c6 69 f0 ?? ?? ?? 01 42 83 fa 04 72 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=5
 
}