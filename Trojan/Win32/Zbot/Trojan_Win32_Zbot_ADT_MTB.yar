
rule Trojan_Win32_Zbot_ADT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 55 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 e3 } //10
		$a_80_1 = {66 65 6b 6f 76 69 6d 6f 66 6f 6a 69 74 75 7a 75 77 69 76 75 77 75 62 61 6a 69 79 6f 66 6f 72 69 } //fekovimofojituzuwivuwubajiyofori  1
		$a_80_2 = {62 6f 6d 67 70 69 61 72 75 63 69 2e 69 77 61 } //bomgpiaruci.iwa  1
		$a_80_3 = {43 6f 70 79 72 69 67 68 7a 20 28 43 29 20 32 30 32 31 2c 20 66 75 64 6b 61 67 61 74 } //Copyrighz (C) 2021, fudkagat  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}