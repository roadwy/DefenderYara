
rule Backdoor_Win32_Oderoor_M{
	meta:
		description = "Backdoor:Win32/Oderoor.M,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 63 73 70 78 58 75 69 64 25 00 } //1
		$a_01_1 = {8b 06 80 38 23 75 1a 81 78 01 65 6e 63 23 75 11 6a 05 ff 75 08 8b ce e8 } //1
		$a_01_2 = {0f b6 50 02 0f b6 48 03 03 ca 0f b6 50 01 0f b6 00 03 ca 03 c8 81 f9 02 02 00 00 75 5a 57 56 8d 4d f8 e8 } //1
		$a_01_3 = {8b d8 85 db 75 04 32 c0 eb 6a 56 8d 85 d8 fe ff ff 50 53 c7 85 d8 fe ff ff 28 01 00 00 33 f6 e8 } //1
		$a_01_4 = {33 c9 84 c0 0f 95 c1 89 5d fc 81 c1 01 00 00 80 89 4d f4 0f 31 03 c2 89 45 fc c7 45 f8 02 00 00 00 8d 45 a4 50 8d 45 c4 50 8b cf e8 } //1
		$a_01_5 = {81 ec 24 04 00 00 83 65 fc 00 53 56 57 8b d8 8d 79 fc 8a 03 43 3c 25 75 71 33 f6 88 45 dc 46 8a 03 88 44 35 dc 0f be 44 35 dc 43 46 50 68 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}