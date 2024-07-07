
rule Trojan_Win32_GandCrab_DVK_MTB{
	meta:
		description = "Trojan:Win32/GandCrab.DVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8a 4c 28 03 8a d9 8a f9 80 e3 f0 c0 e1 06 0a 4c 28 02 80 e7 fc c0 e3 02 0a 1c 28 c0 e7 04 0a 7c 28 01 81 3d 90 01 04 be 00 00 00 88 4c 24 13 75 90 00 } //2
		$a_02_1 = {8d 0c f5 04 00 00 00 c7 05 90 01 04 00 00 00 00 03 cf be 20 37 ef c6 89 4d d4 89 75 f4 8b 09 89 4d f0 3d 2c 02 00 00 75 90 09 05 00 a1 90 00 } //2
		$a_02_2 = {8a 54 24 18 03 cb 8d 04 31 8a 0c 31 32 ca 43 81 fb ec 05 00 00 88 08 0f 8e 90 09 06 00 8b 0d 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}