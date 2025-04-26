
rule Trojan_Win32_Ramgad_B{
	meta:
		description = "Trojan:Win32/Ramgad.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {8d 40 00 53 81 c4 04 f0 ff ff 50 83 c4 f8 8b d8 c7 04 24 00 10 00 00 54 8d 44 24 08 50 e8 } //2
		$a_01_1 = {51 58 4a 74 59 57 64 6c 5a 47 52 76 54 67 3d 3d } //2 QXJtYWdlZGRvTg==
		$a_01_2 = {54 58 6b 67 62 6d 46 74 5a 53 42 70 63 79 42 42 63 6d 31 68 5a 32 56 6b 5a 47 39 } //2 TXkgbmFtZSBpcyBBcm1hZ2VkZG9
		$a_01_3 = {4c 69 34 75 4f 6a 6f 36 51 58 4a 74 59 57 64 6c 5a 47 52 76 54 6a 6f 36 4f 69 34 75 4c 67 3d 3d } //2 Li4uOjo6QXJtYWdlZGRvTjo6Oi4uLg==
		$a_01_4 = {52 32 56 30 54 47 6c 7a 64 44 31 } //2 R2V0TGlzdD1
		$a_01_5 = {55 31 6c 54 56 45 56 4e 58 45 4e } //2 U1lTVEVNXEN
		$a_01_6 = {55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 } //2 U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=10
 
}