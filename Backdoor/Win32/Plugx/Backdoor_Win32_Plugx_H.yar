
rule Backdoor_Win32_Plugx_H{
	meta:
		description = "Backdoor:Win32/Plugx.H,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0c 00 00 "
		
	strings :
		$a_01_0 = {48 48 56 31 00 00 } //1
		$a_01_1 = {48 48 56 32 00 00 } //1
		$a_01_2 = {48 48 56 33 00 00 } //1
		$a_01_3 = {48 48 56 34 00 00 } //1
		$a_01_4 = {46 4b 2d 31 00 00 } //1
		$a_01_5 = {46 4b 2d 32 00 00 } //1
		$a_01_6 = {46 4b 2d 33 00 00 } //1
		$a_01_7 = {46 4b 2d 34 00 00 } //1
		$a_01_8 = {25 00 41 00 55 00 54 00 4f 00 25 00 5c 00 73 00 63 00 72 00 65 00 65 00 6e 00 } //1 %AUTO%\screen
		$a_01_9 = {25 00 41 00 55 00 54 00 4f 00 25 00 5c 00 58 00 58 00 58 00 2d 00 53 00 43 00 52 00 45 00 45 00 4e 00 } //1 %AUTO%\XXX-SCREEN
		$a_03_10 = {66 83 3b 25 56 57 75 ?? 66 83 7b 02 41 75 ?? 66 83 7b 04 55 75 ?? 66 83 7b 06 54 75 ?? 66 83 7b 08 4f 75 ?? 66 83 7b 0a 25 } //10
		$a_03_11 = {80 3c 07 44 75 ?? 80 7c 07 01 5a 75 ?? 80 7c 07 02 4a 75 ?? 80 7c 07 03 53 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*10+(#a_03_11  & 1)*10) >=25
 
}