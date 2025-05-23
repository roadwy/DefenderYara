
rule Trojan_Win32_Meteit_C{
	meta:
		description = "Trojan:Win32/Meteit.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {7e 1c 8b 7c 24 14 8b f5 2b fd 8a 04 37 6a 02 50 e8 8e ff ff ff 83 c4 08 88 06 46 4b 75 ec } //2
		$a_01_1 = {8b 44 24 04 8b 4c 24 08 25 ff 00 00 00 85 c9 7e 0c d1 e0 f6 c4 01 74 02 0c 01 49 75 f4 } //2
		$a_01_2 = {57 00 62 00 65 00 6d 00 53 00 63 00 72 00 69 00 70 00 74 00 69 00 6e 00 67 00 2e 00 53 00 57 00 62 00 65 00 6d 00 4c 00 61 00 73 00 74 00 45 00 72 00 72 00 6f 00 72 00 5c 00 43 00 75 00 72 00 56 00 65 00 72 00 5c 00 } //1 WbemScripting.SWbemLastError\CurVer\
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 } //1 SOFTWARE\Microsoft\Cryptography
		$a_01_4 = {2f 53 70 79 6e 65 74 52 65 70 6f 72 74 53 72 76 63 2e 61 73 6d 78 00 } //1
		$a_01_5 = {2f 72 6f 2f 63 6f 69 6e 2e 70 68 70 00 } //1
		$a_01_6 = {2f 72 69 6d 2f 63 65 64 2e 70 68 70 00 } //1
		$a_03_7 = {2e 30 3c 7c 3e ?? ?? ?? ?? ?? ?? ?? 3c 7c 3e 30 3c 7c 3e 00 } //1
		$a_01_8 = {3c 7c 3e 73 6f 6c 5f } //1 <|>sol_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}