
rule Trojan_Win32_FlyStudio_ASDF_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.ASDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {44 65 61 72 20 43 72 61 63 6b 65 72 20 2c 20 50 6c 65 61 73 65 20 69 6d 6d 65 64 69 61 74 65 6c 79 20 73 74 6f 70 20 74 68 65 20 61 6e 74 69 20 63 6f 6d 70 69 6c 65 72 20 62 65 68 61 76 69 6f 72 } //1 Dear Cracker , Please immediately stop the anti compiler behavior
		$a_01_1 = {41 6e 74 69 20 63 72 61 63 6b 69 6e 67 20 73 65 72 76 69 63 65 20 42 79 } //1 Anti cracking service By
		$a_01_2 = {77 77 77 2e 79 6f 75 2d 6d 2e 63 6f 6d 2f 64 6f 2e 61 73 70 78 } //1 www.you-m.com/do.aspx
		$a_01_3 = {38 64 30 37 30 62 64 66 31 36 35 33 38 62 34 } //1 8d070bdf16538b4
		$a_01_4 = {44 6f 6e 27 74 20 74 72 79 20 64 6f 20 69 74 21 } //1 Don't try do it!
		$a_03_5 = {6a 13 68 32 8a 01 16 68 01 00 01 52 e8 ?? ?? ?? 00 83 c4 10 68 01 03 00 80 6a 00 50 68 0e 00 01 00 68 32 8a 01 16 68 01 00 01 52 68 02 00 00 00 bb } //2
		$a_03_6 = {83 c4 04 6a 00 ff 75 f0 6a ff 6a 08 68 a6 05 02 16 68 01 00 01 52 e8 ?? ?? ?? 00 83 c4 18 8b 5d f0 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*2+(#a_03_6  & 1)*2) >=7
 
}