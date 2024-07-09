
rule TrojanDropper_Win32_Small_NBX{
	meta:
		description = "TrojanDropper:Win32/Small.NBX,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c9 8d 85 fd fe ff ff 38 8d fc fe ff ff 74 07 8a 10 40 84 d2 75 f9 48 6a 01 c6 00 5c 88 48 01 8d 85 fc fe ff ff 50 ff 75 14 ff 75 08 68 ?? ?? ?? ?? 51 ff 15 } //1
		$a_03_1 = {8b 44 8e e8 89 44 8f e8 8b 44 8e ec 89 44 8f ec 8b 44 8e f0 89 44 8f f0 8b 44 8e f4 89 44 8f f4 8b 44 8e f8 89 44 8f f8 8b 44 8e fc 89 44 8f fc 8d 04 8d 00 00 00 00 03 f0 03 f8 ff 24 95 ?? ?? 00 10 } //1
		$a_03_2 = {83 c6 03 83 c7 03 83 f9 08 72 cc f3 a5 ff 24 95 ?? ?? 00 10 8d 49 00 23 d1 8a 06 88 07 8a 46 01 c1 e9 02 88 47 01 83 c6 02 83 c7 02 83 f9 08 72 a6 f3 a5 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}