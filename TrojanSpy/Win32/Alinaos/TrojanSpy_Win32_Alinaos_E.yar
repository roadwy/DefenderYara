
rule TrojanSpy_Win32_Alinaos_E{
	meta:
		description = "TrojanSpy:Win32/Alinaos.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 6c 69 6e 61 20 76 90 0f 01 00 2e 90 0f 01 00 90 00 } //1
		$a_01_1 = {28 28 28 25 3f 5b 42 62 c2 b4 60 5d 3f 29 5b 30 2d 39 5d 7b 31 33 2c 31 39 7d 5c 5e 5b 41 2d 5a 61 2d 7a 5c 73 5d 7b 30 2c 32 36 7d 2f 5b 41 2d 5a 61 2d 7a 5c 73 5d 7b 30 2c 32 36 7d 5c 5e 28 31 5b 32 2d 39 5d 29 28 30 5b 31 2d 39 5d 7c 31 5b 30 2d 32 5d 29 5b 30 2d 39 5c 73 5d 7b 33 2c 35 30 7d 5c 3f 29 5b 3b 5c 73 5d 7b 31 2c 33 7d 28 5b 30 2d 39 5d 7b 31 33 2c 31 39 7d 3d 28 31 5b 32 2d 39 5d 29 28 30 5b 31 2d 39 5d 7c 31 5b 30 2d 32 5d 29 5b 30 2d 39 5d 7b 33 2c 35 30 7d 5c 3f 29 29 } //1
		$a_03_2 = {c7 01 00 00 00 00 6a 00 6a 00 6a 00 6a 01 68 90 01 04 ff 15 90 01 04 89 45 90 01 01 85 c0 0f 84 90 01 04 83 f8 ff 0f 84 90 01 04 6a 00 6a 00 6a 03 6a 00 6a 00 53 56 50 ff 15 90 00 } //3
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3) >=4
 
}