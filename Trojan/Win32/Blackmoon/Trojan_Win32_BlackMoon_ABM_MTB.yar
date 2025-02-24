
rule Trojan_Win32_BlackMoon_ABM_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 07 47 08 c0 74 dc 89 f9 79 07 0f b7 07 47 50 47 b9 57 48 f2 ae 55 ff 96 3c 64 2d 00 09 c0 74 07 89 03 83 c3 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_BlackMoon_ABM_MTB_2{
	meta:
		description = "Trojan:Win32/BlackMoon.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_03_0 = {56 68 00 01 00 84 8d 94 24 9c 00 00 00 52 ff 15 ?? ?? ?? ?? 8b 4c 24 18 50 8d 84 24 a0 00 00 00 50 51 55 ff 15 } //2
		$a_01_1 = {6a 00 6a 00 50 56 51 6a 01 ff d3 8b 4c 24 18 8d 54 24 14 52 55 8d 04 37 50 51 ff 15 } //1
		$a_03_2 = {83 c4 04 58 a3 ?? ?? ?? ?? b8 5b 25 47 00 50 8b 1d ?? ?? ?? ?? 85 db 74 09 53 e8 ?? ?? ?? ?? 83 c4 04 58 } //3
		$a_01_3 = {35 37 42 31 36 43 33 46 2d 38 45 42 31 2d 34 34 38 37 2d 42 31 34 37 2d 43 43 37 34 36 41 30 42 38 38 37 37 } //4 57B16C3F-8EB1-4487-B147-CC746A0B8877
		$a_01_4 = {42 38 36 39 37 30 36 42 34 32 46 30 43 32 30 32 45 35 36 36 37 46 32 32 44 41 31 43 39 43 46 35 } //5 B869706B42F0C202E5667F22DA1C9CF5
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3+(#a_01_3  & 1)*4+(#a_01_4  & 1)*5) >=15
 
}