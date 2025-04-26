
rule Trojan_Win32_Delflob_I{
	meta:
		description = "Trojan:Win32/Delflob.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_02_0 = {c7 45 e8 01 00 00 00 8d 45 ?? 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 ?? ?? ?? ff 8b 55 ?? 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 4d ?? 75 d6 } //1
		$a_02_1 = {c7 45 e8 01 00 00 00 8d 85 ?? ?? ff ff 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 ?? ?? ?? ff 8b 95 ?? ?? ff ff 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 4d ?? 75 d0 } //1
		$a_02_2 = {c7 45 e8 01 00 00 00 8d 85 ?? ?? ff ff 8b 55 fc 8b 4d e8 8a 54 0a ff 8a 4d fb 32 d1 e8 ?? ?? ?? ff 8b 95 ?? ?? ff ff 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 8d ?? ?? ff ff 75 cd } //1
		$a_02_3 = {c7 45 e8 01 00 00 00 8d 45 ?? 8a 55 fb 8b 4d fc 8b 5d e8 8a 4c 19 ff 32 d1 e8 ?? ?? ?? ff 8b 55 ?? 8d 45 f0 e8 ?? ?? ?? ff ff 45 e8 ff 4d ?? 75 d6 } //1
		$a_03_4 = {c7 45 e8 01 00 00 00 8d 85 ?? ?? ff ff 8b 55 e8 8b 4d fc 4a 85 c9 74 05 3b 51 fc 72 05 e8 ?? ?? ff ff 42 8a 54 11 ff 8a 4d fb 32 d1 e8 ?? ?? ff ff 8b 95 ?? ?? ff ff 8d 45 f0 e8 ?? ?? ff ff ff 45 ?? ff 4d ?? 75 c0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_03_4  & 1)*1) >=1
 
}