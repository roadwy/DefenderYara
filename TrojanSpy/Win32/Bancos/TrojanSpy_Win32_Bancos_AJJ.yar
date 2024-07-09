
rule TrojanSpy_Win32_Bancos_AJJ{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 50 6a 00 6a 00 e8 ?? ?? ?? ?? e8 } //1
		$a_01_1 = {b3 2b 39 25 2a 5e 39 5f 2a 21 2c 5d 2a 29 5f 40 5f 39 24 7b 26 2d 39 2b 26 5d 40 39 24 23 25 39 5f 2a 21 2c 5d 2a 29 5f 26 2c 3d 39 24 7b 40 39 2b 26 5d 40 39 29 3d 29 26 2c } //1
		$a_01_2 = {2d 2d 6e 6f 2d 73 74 61 72 74 75 70 2d 77 69 6e 64 6f 77 20 2d 2d 6c 6f 61 64 2d 65 78 74 65 6e 73 69 6f 6e 3d 22 00 00 ff ff ff ff 08 00 00 00 5c 47 6f 6f 67 6c 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}