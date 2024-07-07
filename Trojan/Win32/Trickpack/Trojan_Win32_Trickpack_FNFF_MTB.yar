
rule Trojan_Win32_Trickpack_FNFF_MTB{
	meta:
		description = "Trojan:Win32/Trickpack.FNFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a d4 89 15 1c fc 48 00 8b c8 81 e1 ff 00 00 00 89 0d 18 fc 48 00 c1 e1 08 03 ca 89 0d 14 fc 48 00 c1 e8 10 a3 10 fc 48 00 } //10
		$a_00_1 = {8b 7e 50 83 c1 0c 83 64 39 fc 00 8b 3d 50 c6 48 00 8b 1d 54 c6 48 00 42 03 df 3b d3 7c e2 } //10
		$a_80_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 72 73 64 6e 2e 72 75 } //http://www.rsdn.ru  1
		$a_80_3 = {50 69 63 74 75 72 65 45 78 44 65 6d 6f 2e 45 58 45 } //PictureExDemo.EXE  1
	condition:
		((#a_01_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=22
 
}