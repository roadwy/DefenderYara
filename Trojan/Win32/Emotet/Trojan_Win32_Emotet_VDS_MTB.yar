
rule Trojan_Win32_Emotet_VDS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8b c3 c1 e8 05 03 45 88 8b cb c1 e1 04 03 4d 8c 33 c1 8b 4d 98 03 cb 33 c1 2b f8 81 7d a4 61 0e 00 00 73 } //2
		$a_00_1 = {8b ff 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 38 40 3b c6 7c } //2
		$a_02_2 = {33 c5 89 45 fc c7 05 ?? ?? ?? ?? 30 5a 0a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 c8 89 0d 90 09 05 00 a1 } //2
		$a_02_3 = {8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}