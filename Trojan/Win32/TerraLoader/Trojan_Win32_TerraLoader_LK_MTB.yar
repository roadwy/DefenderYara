
rule Trojan_Win32_TerraLoader_LK_MTB{
	meta:
		description = "Trojan:Win32/TerraLoader.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {c1 e3 02 8b 5c 1d 00 8b 7c 24 ?? ?? ?? ?? 81 e7 ff ff ff 00 31 fb 89 5c 24 ?? 8b 1c 24 43 89 1c 24 eb } //1
		$a_03_1 = {ff 74 24 08 8b 5c 24 04 8b 2d ?? ?? ?? ?? c1 e3 02 58 89 44 1d 00 ff 04 24 71 85 } //1
		$a_01_2 = {81 fb 4d 5a 00 00 74 0a 31 c0 0f be c0 e9 b3 03 00 00 8b 5c 24 08 8b 2c 24 03 5d 3c 89 5c 24 04 8b 6c 24 04 0f bf 5d 04 81 fb 4c 01 00 00 74 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}