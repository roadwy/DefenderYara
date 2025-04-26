
rule Trojan_Win32_CryptInject_BQ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {40 53 65 74 56 69 63 65 43 69 74 69 65 73 7a 40 30 } //1 @SetViceCitiesz@0
		$a_03_1 = {8b ff 8b c6 e8 ?? ?? ff ff 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 0b 6a 00 8d 85 ?? ?? ff ff 50 ff d7 46 3b 35 ?? ?? ?? 00 72 d9 } //1
		$a_03_2 = {88 14 01 c3 90 0a 1f 00 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}