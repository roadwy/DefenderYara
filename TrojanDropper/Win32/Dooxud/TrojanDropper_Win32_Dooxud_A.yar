
rule TrojanDropper_Win32_Dooxud_A{
	meta:
		description = "TrojanDropper:Win32/Dooxud.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 85 ?? ?? ff ff 8a 10 32 94 8d ?? ?? ff ff 8b 45 08 03 85 ?? ?? ff ff 88 10 e9 ?? ff ff ff } //2
		$a_03_1 = {33 c0 66 8b 02 3d 4d 5a 00 00 74 05 e9 ?? ?? 00 00 8b 0d ?? ?? ?? 00 8b 55 0c 03 51 3c 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 81 38 50 45 00 00 74 05 e9 ?? ?? 00 00 } //1
		$a_03_2 = {33 d2 66 8b 11 81 fa 4d 5a 00 00 74 05 e9 ?? ?? 00 00 a1 ?? ?? ?? 00 8b 4d 0c 03 48 3c 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 81 3a 50 45 00 00 74 05 e9 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}