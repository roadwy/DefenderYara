
rule Trojan_Win32_Zbot_DM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {a1 d4 f2 e0 14 85 c0 75 06 ff 15 1c f1 e0 14 8b 4c 24 08 69 c0 fd 43 03 00 2b 4c 24 04 05 c3 9e 26 00 a3 d4 f2 e0 14 41 33 d2 f7 f1 8b c2 03 44 24 04 } //1
		$a_00_1 = {39 45 f8 76 1d 8a c8 02 c9 a8 01 75 09 b2 f6 2a d1 00 14 38 eb 06 80 c1 07 00 0c 38 40 3b 45 f8 72 e3 } //1
		$a_81_2 = {6f 75 74 70 6f 73 74 2e 65 78 65 } //1 outpost.exe
		$a_81_3 = {77 73 6e 70 6f 65 6d 61 2e 65 78 65 } //1 wsnpoema.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Zbot_DM_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {fe c3 36 8a 94 2b 00 fc ff ff 02 c2 36 8a 8c 28 00 fc ff ff 36 88 8c 2b 00 fc ff ff 36 88 94 28 00 fc ff ff 02 ca 36 8a 8c 29 00 fc ff ff 30 0e 46 4f 75 cc } //1
		$a_01_1 = {44 65 63 72 79 70 74 4d 65 73 73 61 67 65 } //1 DecryptMessage
		$a_01_2 = {48 4f 53 54 32 3a 38 30 2e 38 35 2e 38 34 2e 37 39 } //1 HOST2:80.85.84.79
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 69 70 34 2e 73 65 65 69 70 2e 6f 72 67 } //1 https://ip4.seeip.org
		$a_01_4 = {31 39 34 2e 31 30 39 2e 32 30 36 2e 32 31 32 } //1 194.109.206.212
		$a_01_5 = {31 33 31 2e 31 38 38 2e 34 30 2e 31 38 39 } //1 131.188.40.189
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}