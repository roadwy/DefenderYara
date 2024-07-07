
rule Backdoor_Win32_Kriskynote_A{
	meta:
		description = "Backdoor:Win32/Kriskynote.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 66 0f 1f 84 00 00 00 00 00 40 30 3b 48 ff c3 40 fe c7 48 ff c9 75 f2 48 8b cd ff 15 } //1
		$a_01_1 = {41 0f b6 0b ff c3 49 ff c3 80 f1 36 0f b6 c1 c0 e9 04 c0 e0 04 02 c1 41 88 43 ff } //1
		$a_01_2 = {49 6e 73 74 61 6c 6c 5f 75 61 63 } //1 Install_uac
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Kriskynote_A_2{
	meta:
		description = "Backdoor:Win32/Kriskynote.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {f7 de 83 f8 01 75 1d 33 c0 85 f6 7e 17 8a 4c 24 13 8a 14 28 32 d1 fe c1 88 14 28 40 3b c6 88 4c 24 13 7c e9 57 ff 15 } //2
		$a_11_1 = {00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 4e 00 74 00 55 00 73 00 65 00 72 00 45 00 78 00 01 } //1 礀猀琀攀洀㌀㈀尀一琀唀猀攀爀䔀砀Ā
		$a_8a_2 = {31 } //5376 1
	condition:
		((#a_01_0  & 1)*2+(#a_11_1  & 1)*1+(#a_8a_2  & 1)*5376) >=3
 
}