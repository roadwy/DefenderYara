
rule Trojan_Win32_Zusy_LMH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 88 45 a3 8d 85 7c fd ff ff 8d 55 a3 89 14 24 c7 85 e8 fb ff ff 04 00 00 00 89 c1 } //20
		$a_03_1 = {8d 85 64 fd ff ff c7 44 24 ?? ?? ?? ?? ?? 8d 55 a4 89 54 24 04 89 04 24 c7 85 e8 fb ff ff 06 00 00 00 } //10
		$a_01_2 = {89 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 88 85 e0 fb ff ff 8b 55 dc 8d 85 7c fd ff ff 89 14 24 89 c1 } //5
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}