
rule Trojan_Win32_TrickBotCrypt_GK_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 08 33 ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 0f af 35 ?? ?? ?? ?? 8b 7d f4 2b fe 03 3d ?? ?? ?? ?? 03 3d ?? ?? ?? ?? 2b f8 2b 3d ?? ?? ?? ?? 2b fa 03 3d ?? ?? ?? ?? 03 3d ?? ?? ?? ?? 8b 55 0c 88 0c 3a } //1
		$a_81_1 = {31 51 6a 58 3c 57 6c 45 57 7a 48 5f 59 5f 67 41 58 47 67 38 49 75 31 69 42 7a 6d 30 6f 79 43 69 44 21 64 49 75 26 62 28 32 75 58 31 70 55 68 30 4c 33 6a 33 35 79 40 79 36 53 30 54 72 37 70 4e 30 72 77 32 42 65 26 32 66 58 4a 79 21 67 55 50 39 73 57 78 2a 53 69 62 71 7a 5a 57 69 78 65 } //1 1QjX<WlEWzH_Y_gAXGg8Iu1iBzm0oyCiD!dIu&b(2uX1pUh0L3j35y@y6S0Tr7pN0rw2Be&2fXJy!gUP9sWx*SibqzZWixe
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}