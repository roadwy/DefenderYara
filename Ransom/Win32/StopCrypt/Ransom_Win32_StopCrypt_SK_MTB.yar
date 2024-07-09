
rule Ransom_Win32_StopCrypt_SK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 1f 33 4d ?? 89 35 ?? ?? ?? ?? 33 4d ?? 89 4d ?? 8b 45 } //1
		$a_03_1 = {8b ec 8b 45 ?? 8b 4d ?? 31 08 5d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Ransom_Win32_StopCrypt_SK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {ff 8b 85 30 ff ff ff 81 45 d4 aa a4 ab 79 81 45 70 39 2d 8e 45 81 85 24 ff ff ff a6 98 53 58 81 6d 08 9e b9 8b 52 81 ad b0 fe ff ff 03 72 47 4d } //2
		$a_02_1 = {f7 65 b0 8b 45 b0 81 45 0c ?? ?? ?? ?? 81 ad fc fe ff ff ?? ?? ?? ?? 81 45 bc ?? ?? ?? ?? 8b 85 80 00 00 00 30 0c 30 b8 01 00 00 00 83 f0 04 83 ad 80 00 00 00 01 39 bd 80 00 00 00 0f 8d ?? ?? ff ff } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}