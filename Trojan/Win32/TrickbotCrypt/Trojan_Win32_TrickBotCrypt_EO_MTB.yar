
rule Trojan_Win32_TrickBotCrypt_EO_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 0e 03 df 8a 04 0b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8d 45 ff 0f af 05 ?? ?? ?? ?? 03 ea 03 c5 8b 6c 24 1c 8a 14 08 8b 44 24 10 8a 1c 28 32 da 8b 54 24 20 88 1c 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBotCrypt_EO_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d3 2b 15 ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 83 c2 02 0f af d0 8b 44 24 1c 03 d5 03 c2 8b 54 24 10 8a 14 0a 02 d3 30 10 } //1
		$a_81_1 = {64 6e 63 53 6a 42 23 7a 36 4b 6b 30 74 5a 44 4e 2a 51 21 28 4c 67 36 72 44 6a 21 79 6c 5a 6e 34 5f 5e 4c 24 78 50 71 39 25 45 48 73 6f 6a 6f 3c 48 6f 47 62 6c 4c 79 47 6f 65 76 4f 67 63 72 51 25 47 73 41 4e 45 21 } //1 dncSjB#z6Kk0tZDN*Q!(Lg6rDj!ylZn4_^L$xPq9%EHsojo<HoGblLyGoevOgcrQ%GsANE!
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}