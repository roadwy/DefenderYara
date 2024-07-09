
rule Trojan_Win32_TrickbotCrypt_SN_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 a3 ?? ?? ?? ?? 33 d2 33 c0 8b 0d ?? ?? ?? ?? 88 04 01 40 3d ?? ?? ?? ?? 7c } //1
		$a_03_1 = {0f b6 04 0e 0f b6 da 8b 54 24 ?? 0f b6 14 13 03 d7 03 c2 99 bf ?? ?? 00 00 f7 ff 8a 04 0e 83 c1 02 0f b6 fa 8a 14 37 88 54 0e ?? 88 04 37 8d 2c 37 8d 43 01 99 f7 7c 24 ?? 8b 35 ?? ?? ?? ?? 8b 44 24 ?? 0f b6 da 0f b6 14 03 0f b6 44 0e ?? 03 d7 03 c2 99 bf ?? ?? 00 00 f7 ff 8a 44 0e ?? 0f b6 fa 8a 14 37 8d 2c 37 88 54 0e ?? 88 45 00 8d 43 ?? 99 f7 7c 24 18 81 f9 ?? ?? 00 00 0f 8c } //1
		$a_03_2 = {0f b6 54 24 ?? a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 ?? 30 0c 03 8b 44 24 ?? 43 3b d8 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}