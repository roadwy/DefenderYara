
rule Trojan_Win32_Plubea_B{
	meta:
		description = "Trojan:Win32/Plubea.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {68 4a 0d ce 09 e8 } //1
		$a_01_1 = {68 d0 03 5c 09 e8 } //1
		$a_01_2 = {68 f4 15 93 b0 e8 } //1
		$a_01_3 = {68 31 74 bc 7f e8 } //1
		$a_01_4 = {68 b0 06 6a 90 e8 } //1
		$a_01_5 = {68 9c b8 ba a6 57 e8 } //1
		$a_01_6 = {68 78 5c 3b 55 e8 } //1
		$a_01_7 = {68 65 41 fb a7 e8 } //1
		$a_01_8 = {6a 40 68 00 30 00 00 8b 46 50 50 8b 46 34 50 ff d7 } //1
		$a_03_9 = {25 61 70 70 64 61 74 61 25 5c 46 6c 61 73 68 50 6c 61 79 65 72 00 [0-08] 5c 70 6c 75 67 31 2e 64 61 74 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*1) >=10
 
}