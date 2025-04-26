
rule TrojanDropper_Win32_Monkif_G{
	meta:
		description = "TrojanDropper:Win32/Monkif.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f4 4c c6 45 f5 6f c6 45 f6 63 c6 45 f7 61 c6 45 f8 6c c6 45 f9 5c c6 45 fa 55 c6 45 fb 49 c6 45 fc 45 c6 45 fd 49 } //2
		$a_03_1 = {00 04 00 00 74 de 81 3d ?? ?? ?? ?? 01 04 00 00 74 d2 90 09 06 00 81 3d } //1
		$a_03_2 = {8d 46 fe 83 c4 ?? 3d 04 af 22 00 7c } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}