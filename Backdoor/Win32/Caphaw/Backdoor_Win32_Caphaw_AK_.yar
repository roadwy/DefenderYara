
rule Backdoor_Win32_Caphaw_AK_{
	meta:
		description = "Backdoor:Win32/Caphaw.AK!!Caphaw,SIGNATURE_TYPE_ARHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {b9 4d 5a 00 00 33 c0 66 39 0a 75 30 8b 4a 3c 03 ca 81 39 50 45 00 00 75 23 85 f6 74 05 8d 41 04 89 06 85 ff 74 05 8d 41 18 89 07 85 db 74 0a 0f b7 41 14 8d 44 08 18 89 03 } //2
		$a_01_1 = {83 e8 08 a9 fe ff ff ff 76 39 8b 45 fc 0f b7 44 41 08 8b f8 81 e7 00 f0 00 00 bb 00 30 00 00 66 3b fb 75 0f 25 ff 0f 00 00 03 01 8b fa 2b 7e 1c 01 3c 10 8b 41 04 } //2
		$a_01_2 = {8b 7e 04 8d 4f 01 3b c1 72 16 8b 06 8b 55 08 8d 3c b8 33 c0 ab 8b 46 04 8b 0e 89 14 81 ff 46 04 } //2
		$a_01_3 = {41 56 43 49 6e 6a 50 61 63 6b 40 40 } //1 AVCInjPack@@
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}