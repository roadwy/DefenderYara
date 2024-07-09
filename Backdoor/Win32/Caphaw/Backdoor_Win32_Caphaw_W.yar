
rule Backdoor_Win32_Caphaw_W{
	meta:
		description = "Backdoor:Win32/Caphaw.W,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d6 a8 02 ?? ?? 6a 00 ff 15 ?? ?? ?? ?? ff d6 a8 02 74 f2 } //2
		$a_03_1 = {89 45 fc 8b c8 8b 45 ?? 8b d1 c1 e9 02 8b f0 8b fb f3 a5 83 c4 10 6a 00 6a 00 8b ca 83 e1 03 6a 00 f3 a4 6a 00 89 45 e4 ff 15 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 8b f0 85 f6 } //1
		$a_03_2 = {8d 45 ec 50 6a 00 8d 4d e0 51 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 75 13 8b 55 fc 8b 75 ?? 52 56 56 e8 ?? ?? ff ff 83 c4 0c eb ?? 68 e8 03 00 00 56 ff d7 3d 02 01 00 00 74 ?? 6a 02 56 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}