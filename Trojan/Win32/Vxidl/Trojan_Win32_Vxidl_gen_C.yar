
rule Trojan_Win32_Vxidl_gen_C{
	meta:
		description = "Trojan:Win32/Vxidl.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {7e 3c bf 01 00 00 00 8d 45 ec 8b 55 fc 8a 54 3a ff 8b 4d f8 32 54 19 ff e8 } //4
		$a_00_1 = {6c 6b 72 65 6d 65 33 34 35 } //4 lkreme345
		$a_00_2 = {ff ff 50 6a 00 6a 00 68 25 80 00 00 6a 00 e8 } //2
		$a_02_3 = {40 00 8b c0 53 33 db 6a 00 e8 ?? ?? ff ff 83 f8 07 75 } //2
		$a_02_4 = {8b 55 f0 8d 45 f4 e8 ?? ?? ff ff 6a 00 68 80 00 00 00 6a 04 6a 00 6a 00 68 00 00 00 40 8b 45 fc } //2
		$a_00_5 = {23 31 00 00 23 32 00 00 53 4f 46 54 57 41 52 45 } //2
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*4+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2+(#a_00_5  & 1)*2) >=8
 
}