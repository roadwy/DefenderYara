
rule Trojan_Win32_Vidar_AK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {3e e3 b4 f3 0d 96 e4 e0 cf 4d a9 3d bf 41 07 df 86 b9 43 4a 52 d7 32 1e 63 95 fe 86 50 05 98 8c fa 7f de bd b1 56 43 de 99 23 30 fe 70 68 dc 21 45 f0 c9 b5 f9 4e 87 f4 87 02 00 01 00 00 0b 51 d1 } //3
		$a_01_1 = {6c 00 69 00 63 00 65 00 6e 00 73 00 65 00 2e 00 6b 00 65 00 79 00 } //1 license.key
		$a_01_2 = {46 00 49 00 4c 00 45 00 46 00 55 00 4e 00 43 00 } //1 FILEFUNC
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}