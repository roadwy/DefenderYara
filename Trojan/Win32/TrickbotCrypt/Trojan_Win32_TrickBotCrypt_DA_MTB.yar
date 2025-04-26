
rule Trojan_Win32_TrickBotCrypt_DA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0e 0f b6 0c 0f 03 c1 99 b9 ?? ?? ?? ?? f7 f9 88 54 24 ?? ff d3 ff d3 ff d3 0f b6 54 24 ?? 8b 0d ?? ?? ?? ?? 8b 44 24 ?? 8a 14 0a 30 14 28 } //1
		$a_03_1 = {8a 04 33 f6 d0 8b ce 3b f7 73 ?? 8a d9 2a da 32 19 32 d8 88 19 03 4d ?? 3b cf 72 ?? 8b 5d ?? 46 ff 4d ?? 75 } //1
		$a_03_2 = {8a 04 33 f6 d0 8b ce 3b 75 ?? 73 ?? 8a d9 2a da 32 19 32 d8 88 19 03 cf 3b 4d ?? 72 ?? 8b 5d ?? 46 ff 4d ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}