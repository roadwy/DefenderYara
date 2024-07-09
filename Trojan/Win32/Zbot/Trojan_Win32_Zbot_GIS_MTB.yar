
rule Trojan_Win32_Zbot_GIS_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 0d 9c 4a 40 00 8b 15 94 4a 40 00 8b 45 08 89 04 8a 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? 33 c0 eb 03 83 c8 ff 5d c3 } //10
		$a_01_1 = {8b d0 8b 5d f0 33 c0 42 8b 0a 40 fe c1 fe c9 75 f6 48 c3 } //10
		$a_80_2 = {43 3a 5c 76 69 72 75 73 2e 65 78 65 } //C:\virus.exe  1
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10+(#a_80_2  & 1)*1) >=21
 
}