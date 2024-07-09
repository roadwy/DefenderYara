
rule Trojan_Win32_Azorult_VSD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.VSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b 95 dc f3 ff ff 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 89 0d ?? ?? ?? ?? c1 e8 10 30 04 13 43 3b df 7c } //2
		$a_02_1 = {8d 34 07 e8 ?? ?? ?? ?? 30 06 83 6d fc 01 8b 45 fc 85 c0 7d } //2
		$a_02_2 = {31 7c 24 10 8b f5 c1 ee 05 03 74 24 38 81 3d ?? ?? ?? ?? b4 11 00 00 75 90 09 0a 00 c7 05 } //2
		$a_00_3 = {8b c7 f7 f3 8b 44 24 10 8a 04 02 30 01 47 3b 7c 24 18 0f 85 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}