
rule Backdoor_Win32_Coroxy_E{
	meta:
		description = "Backdoor:Win32/Coroxy.E,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 09 00 00 "
		
	strings :
		$a_03_0 = {78 6f 72 64 75 ?? 81 3d ?? ?? ?? ?? 61 74 61 00 75 ?? 83 7d 10 00 } //10
		$a_01_1 = {81 3c 30 2e 62 69 74 0f 85 } //10
		$a_01_2 = {66 b8 2e 00 aa 66 b8 65 00 aa 66 b8 78 00 aa 66 b8 65 00 aa b8 00 00 00 00 } //10
		$a_01_3 = {8b 75 08 8b 7d 0c 32 c0 eb 03 a4 aa 49 0b c9 75 f9 8d 04 55 00 00 00 00 } //5
		$a_01_4 = {33 c0 33 db 8a 1e 46 80 fb 30 72 0f 80 fb 39 77 0a 80 eb 30 f7 } //5
		$a_01_5 = {8b 55 10 88 02 8a 07 30 02 ff 45 10 eb 02 30 07 49 83 } //5
		$a_03_6 = {b8 fc fd fe ff b9 40 00 00 00 ?? ?? ?? ?? ?? ?? ?? 2d 04 04 04 04 } //5
		$a_01_7 = {8b 45 08 ab 8b 45 0c ab 8b 45 14 ab 8b 45 18 ab b8 01 00 00 00 } //2
		$a_01_8 = {8b 08 8b 51 08 50 ff d2 8b 45 f8 8b 08 8b 51 08 50 ff d2 8b 45 fc 8b 08 8b 51 08 50 ff d2 } //2
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_03_6  & 1)*5+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=26
 
}