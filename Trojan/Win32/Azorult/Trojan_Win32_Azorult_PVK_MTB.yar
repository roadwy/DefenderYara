
rule Trojan_Win32_Azorult_PVK_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {25 ff 00 00 00 81 3d 90 01 04 21 06 00 00 a3 90 01 04 75 90 09 0d 00 0f b6 81 90 01 04 03 05 90 00 } //2
		$a_02_1 = {0f b6 d3 03 f2 81 e6 ff 00 00 00 81 3d 90 01 04 81 0c 00 00 75 90 09 07 00 0f b6 b0 90 00 } //2
		$a_02_2 = {8b 44 24 10 81 44 24 1c 90 01 04 33 c6 2b e8 ff 4c 24 28 89 44 24 10 0f 85 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}