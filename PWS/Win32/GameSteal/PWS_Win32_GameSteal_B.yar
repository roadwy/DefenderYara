
rule PWS_Win32_GameSteal_B{
	meta:
		description = "PWS:Win32/GameSteal.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {2e 61 73 70 00 } //1
		$a_01_1 = {25 73 5c 2e 2e 5c 57 54 46 5c 43 6f 6e 66 69 67 2e 77 74 66 } //1 %s\..\WTF\Config.wtf
		$a_00_2 = {4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 Microsoft Internet Explorer
		$a_01_3 = {53 68 61 6e 64 61 5c 4c 65 67 65 6e 64 20 6f 66 20 4d 69 72 } //1 Shanda\Legend of Mir
		$a_01_4 = {45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 5c 57 6f 72 6c 64 20 6f 66 20 57 61 72 63 72 61 66 74 } //1 Entertainment\World of Warcraft
		$a_00_5 = {00 6d 69 72 2e } //1
		$a_01_6 = {45 78 70 6c 6f 72 65 72 5c 77 73 6f 63 6b 33 32 2e 64 6c 6c } //1 Explorer\wsock32.dll
		$a_01_7 = {8a c2 8a ca c0 e8 04 80 e1 0f 3c 0a 73 04 04 30 eb 02 04 37 } //1
		$a_01_8 = {00 10 8d 48 05 a3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=8
 
}