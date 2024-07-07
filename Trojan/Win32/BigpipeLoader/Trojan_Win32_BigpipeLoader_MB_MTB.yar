
rule Trojan_Win32_BigpipeLoader_MB_MTB{
	meta:
		description = "Trojan:Win32/BigpipeLoader.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c5 89 45 fc 53 8b 5d 0c 33 c0 56 8b 75 08 57 50 68 80 00 00 00 6a 03 50 6a 07 68 00 00 00 80 68 90 01 04 89 03 ff 15 90 00 } //10
		$a_01_1 = {8b 45 f8 8b 4d f4 01 06 2b c8 01 03 89 4d f4 85 c9 75 d9 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}