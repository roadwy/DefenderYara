
rule Trojan_Win32_Racealer_PVS_MTB{
	meta:
		description = "Trojan:Win32/Racealer.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b 4d d0 03 4d f4 8b 51 08 81 f2 7a ae 00 00 8b 45 d0 03 45 f4 89 50 08 } //2
		$a_02_1 = {89 85 c4 f7 ff ff 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 85 ?? f7 ff ff 31 85 ?? f7 ff ff 81 3d ?? ?? ?? ?? 72 07 00 00 75 } //2
		$a_00_2 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 3a 42 3b d6 7c } //2
		$a_00_3 = {0f be 0c 01 89 4d 14 0a 5d 14 f6 d1 0a d1 22 d3 88 10 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}