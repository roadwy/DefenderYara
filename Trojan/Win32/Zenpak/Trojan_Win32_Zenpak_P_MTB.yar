
rule Trojan_Win32_Zenpak_P_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 ec 89 34 24 8b 7d f0 89 7c 24 04 89 44 24 08 0f b6 04 0d ?? ?? ?? ?? 89 44 24 0c 89 55 e4 e8 ?? ?? ?? ?? 8b 45 e4 8b 4d f4 39 c8 89 45 e8 75 bb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Zenpak_P_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 75 cc 32 0c 32 8b 55 ?? 88 0c 32 } //2
		$a_01_1 = {8b 3f 8b 00 0f b7 12 31 fa } //2
		$a_01_2 = {c6 85 d4 fe ff ff 56 c6 85 d5 fe ff ff 69 c6 85 d6 fe ff ff 72 c6 85 d7 fe ff ff 74 c6 85 d8 fe ff ff 75 c6 85 d9 fe ff ff 61 c6 85 da fe ff ff 6c c6 85 db fe ff ff 41 c6 85 dc fe ff ff 6c c6 85 dd fe ff ff 6c c6 85 de fe ff ff 6f c6 85 df fe ff ff 63 } //2
		$a_01_3 = {c6 45 d4 56 c6 45 d5 69 c6 45 d6 72 c6 45 d7 74 c6 45 d8 75 c6 45 d9 61 c6 45 da 6c c6 45 db 41 c6 45 dc 6c c6 45 dd 6c c6 45 de 6f c6 45 df 63 } //2
		$a_01_4 = {c6 45 94 6b c6 45 95 65 c6 45 96 72 c6 45 97 6e c6 45 98 65 c6 45 99 6c c6 45 9a 33 c6 45 9b 32 c6 45 9c 2e c6 45 9d 64 c6 45 9e 6c c6 45 9f 6c } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=2
 
}