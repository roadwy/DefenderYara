
rule Trojan_Win32_Zbot_GHC_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 c1 0f b6 04 0a 8b 0d 90 01 04 88 01 0f b6 45 e4 33 45 0c 0f b6 4d e0 31 c8 88 45 d8 0f b6 4d e4 a1 90 01 04 0f b6 55 d8 33 d1 83 c2 e9 03 c2 a3 90 01 04 0f b6 4d d8 8b 45 dc 29 c8 8b 4d f8 05 58 ff ff ff 01 c1 89 4d f8 0f b6 45 d8 89 45 d4 0f b6 45 e0 8b 0d 90 01 04 33 45 d4 2d 90 01 04 2b c8 90 00 } //10
		$a_01_1 = {2e 72 6f 70 66 } //1 .ropf
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}