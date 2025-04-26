
rule Trojan_Win32_ChChes_G_dha{
	meta:
		description = "Trojan:Win32/ChChes.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 db 74 19 8d 14 3e 8b 7d fc 8a 0c 11 32 0c 38 40 8b 7d 10 88 0a 8b 4d 08 3b c3 72 e7 3b 75 f8 76 0e 57 68 ?? ?? ?? ?? e8 31 00 00 00 83 c4 08 8b 45 0c 46 8b 4d 08 3b f0 72 c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ChChes_G_dha_2{
	meta:
		description = "Trojan:Win32/ChChes.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 06 00 00 "
		
	strings :
		$a_03_0 = {8d 14 3e 8b 7d ?? 8a 0c 11 32 0c 38 40 8b 7d ?? 88 0a 8b 4d ?? 3b c3 72 e7 } //5
		$a_03_1 = {41 83 f9 04 7c ce 90 09 2c 00 0f b6 81 ?? ?? ?? ?? 30 44 0d ?? 0f b6 81 ?? ?? ?? ?? 30 44 0d ?? 0f b6 81 ?? ?? ?? ?? 30 44 0d ?? 0f b6 81 ?? ?? ?? ?? 30 44 0d } //5
		$a_03_2 = {0f b6 44 8d ?? 0f b6 80 ?? ?? ?? ?? 88 44 8d ?? 0f b6 44 8d ?? 0f b6 80 ?? ?? ?? ?? 88 44 8d ?? 0f b6 44 8d ?? 0f b6 80 ?? ?? ?? ?? 88 44 8d ?? 0f b6 44 8d ?? 0f b6 80 ?? ?? ?? ?? 88 44 8d ?? 41 83 f9 04 7c ba } //3
		$a_03_3 = {0f b6 4c 06 fc 30 4c 05 ?? 0f b6 0c 06 30 4c 05 ?? 0f b6 4c 06 04 30 4c 05 ?? 0f b6 4c 06 08 30 4c 05 ?? 40 83 f8 04 7c d7 85 db 74 09 8d 45 ?? 50 e8 } //3
		$a_01_4 = {8d 00 8d 00 8d 00 8d 00 8d 00 8d 33 c0 33 c9 85 d2 74 17 57 8d a4 24 00 00 00 00 } //10
		$a_01_5 = {c7 45 9c 61 62 65 32 c7 45 a0 38 36 39 66 c7 45 a4 2d 39 62 34 } //10
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*3+(#a_03_3  & 1)*3+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10) >=16
 
}