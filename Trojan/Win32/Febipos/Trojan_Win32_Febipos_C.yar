
rule Trojan_Win32_Febipos_C{
	meta:
		description = "Trojan:Win32/Febipos.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 7b 7d 00 63 6f 75 6e 74 72 79 5f 63 6f 64 65 00 42 52 } //1
		$a_01_1 = {46 61 63 65 62 6f 6f 6b 20 55 70 64 61 74 65 } //1 Facebook Update
		$a_01_2 = {30 42 7a 31 74 64 4d 42 31 77 36 79 64 4e 31 42 4f 62 46 52 53 4d 30 39 76 55 55 30 26 61 6d 70 3b 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 } //1 0Bz1tdMB1w6ydN1BObFRSM09vUU0&amp;export=download
		$a_01_3 = {25 73 5c 66 62 76 69 64 65 6f 70 6c 75 67 69 6e 2e 65 78 65 } //1 %s\fbvideoplugin.exe
		$a_03_4 = {8d 85 c4 e9 ff ff 66 c7 00 58 58 c6 40 02 00 8d 85 d4 fd ff ff 89 04 24 e8 7b 0a 00 00 c7 44 24 04 ?? ?? ?? ?? 8d 85 c4 e9 ff ff 89 04 24 e8 ?? ?? ?? ?? 85 c0 0f 85 0a 02 00 00 8b 45 dc 89 44 24 08 c7 44 24 04 ?? ?? ?? ?? 8d 85 d4 fd ff ff 89 04 24 e8 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=6
 
}