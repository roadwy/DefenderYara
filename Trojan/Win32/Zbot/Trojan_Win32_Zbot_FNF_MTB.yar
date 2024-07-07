
rule Trojan_Win32_Zbot_FNF_MTB{
	meta:
		description = "Trojan:Win32/Zbot.FNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {a1 00 14 46 00 31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 } //10
		$a_80_1 = {66 65 6b 6f 76 69 6d 6f 66 6f 6a 69 74 75 7a 75 77 69 76 75 77 75 62 61 6a 69 79 6f 66 6f 72 69 } //fekovimofojituzuwivuwubajiyofori  1
		$a_80_2 = {70 65 72 61 6c 65 79 75 77 61 77 75 73 6f 67 65 79 6f 64 6f 74 75 } //peraleyuwawusogeyodotu  1
		$a_80_3 = {62 6f 6d 67 70 69 61 72 75 63 69 2e 69 77 61 } //bomgpiaruci.iwa  1
		$a_80_4 = {43 6f 70 79 72 69 67 68 7a 20 28 43 29 20 32 30 32 31 2c 20 66 75 64 6b 61 67 61 74 } //Copyrighz (C) 2021, fudkagat  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}