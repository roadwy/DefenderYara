
rule Trojan_Win32_Zenpak_DSK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75 } //1
		$a_02_1 = {8b 4d 08 30 04 0e 46 3b f7 7c 90 09 05 00 e8 } //1
		$a_00_2 = {8b 4d fc 03 cf 33 c1 2b f0 8b 45 d8 d1 6d f4 29 45 fc ff 4d f0 0f 85 } //2
		$a_02_3 = {8b 54 24 10 8b c7 c1 e8 05 03 44 24 78 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 89 2d } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}