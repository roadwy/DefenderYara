
rule TrojanSpy_Win32_Bafi_J{
	meta:
		description = "TrojanSpy:Win32/Bafi.J,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {0f b6 45 ff 02 98 ?? ?? ?? ?? 40 25 0f 00 00 80 79 05 48 83 c8 f0 40 88 45 ff 8a 01 8a d0 32 d3 88 14 0e } //3
		$a_03_1 = {0f b6 45 fe 0f b6 80 ?? ?? ?? ?? 0f b6 4d ff 03 c8 88 4d ff 0f b6 45 fe 40 25 0f 00 00 80 79 05 48 83 c8 f0 40 88 45 fe 8b 45 ?? 03 45 ?? 0f b6 00 0f b6 4d ff 33 c1 } //3
		$a_01_2 = {54 00 69 00 6d 00 65 00 3a 00 20 00 25 00 73 00 20 00 55 00 72 00 6c 00 3a 00 20 00 25 00 73 00 20 00 52 00 65 00 66 00 65 00 72 00 72 00 65 00 72 00 3a 00 20 00 25 00 73 00 20 00 49 00 45 00 76 00 65 00 72 00 3a 00 20 00 25 00 73 00 20 00 2d 00 2d 00 3e 00 } //2 Time: %s Url: %s Referrer: %s IEver: %s -->
		$a_01_3 = {73 00 73 00 65 00 73 00 5c 00 6c 00 69 00 6e 00 6b 00 72 00 64 00 72 00 2e 00 41 00 49 00 45 00 62 00 68 00 6f 00 } //2 sses\linkrdr.AIEbho
		$a_01_4 = {4d 00 43 00 4c 00 49 00 43 00 4b 00 44 00 42 00 4c 00 00 00 52 00 43 00 4c 00 49 00 43 00 4b 00 00 00 } //2
		$a_01_5 = {3c 00 43 00 4c 00 45 00 41 00 52 00 3e 00 00 00 73 00 68 00 6f 00 77 00 70 00 6f 00 70 00 75 00 70 00 00 00 } //2
		$a_01_6 = {73 00 68 00 6f 00 77 00 70 00 6f 00 70 00 75 00 70 00 00 00 3c 00 43 00 4c 00 45 00 41 00 52 00 3e 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=7
 
}