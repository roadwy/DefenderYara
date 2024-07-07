
rule Trojan_Win32_GandCrab_KSD_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.KSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 55 ff 88 90 a0 56 43 00 0f b6 b1 a0 56 43 00 0f b6 ca 03 f1 3d 2c 87 14 00 76 } //2
		$a_02_1 = {0f b6 45 ff 88 99 90 01 04 0f b6 9a 90 01 04 03 d8 81 f9 2c 87 14 00 76 90 09 0c 00 8b 0d 90 01 04 8b 15 90 00 } //2
		$a_00_2 = {8b cf 8b c7 c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 3b 33 c8 8b 45 e8 2b f1 b9 01 00 00 00 2b c8 03 d9 83 6d fc 01 75 } //2
		$a_02_3 = {8a 81 80 ef 42 00 8a 9a 80 ef 42 00 88 82 80 ef 42 00 81 f9 0a 0d 00 00 73 90 09 0c 00 8b 0d 90 01 04 8b 15 90 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}