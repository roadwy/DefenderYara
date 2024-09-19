
rule Trojan_Win32_BlackMoon_ASGH_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ASGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {8d 2c 03 8a 1c 03 88 1f 88 4d 00 8a 1f 02 d9 81 e3 ff 00 00 00 8a 0c 03 8a 1c 16 32 d9 8b 4c 24 1c 88 1c 16 46 3b f1 7c } //2
		$a_03_1 = {83 c4 04 68 04 00 00 80 6a 00 68 ?? ?? ?? 00 68 01 00 00 00 bb dc 09 00 00 e8 } //2
		$a_01_2 = {31 33 35 20 32 34 35 20 36 32 20 31 34 30 20 32 34 20 31 37 39 20 31 37 30 20 31 33 34 20 32 33 } //2 135 245 62 140 24 179 170 134 23
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}