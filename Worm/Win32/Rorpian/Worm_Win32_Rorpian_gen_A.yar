
rule Worm_Win32_Rorpian_gen_A{
	meta:
		description = "Worm:Win32/Rorpian.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_01_0 = {6d 79 70 6f 72 6e 6f 2e 61 76 69 2e 6c 6e 6b 00 } //1
		$a_01_1 = {70 6f 72 6e 6d 6f 76 73 2e 6c 6e 6b 00 } //1
		$a_01_2 = {73 65 74 75 70 25 75 2e 66 6f 6e 00 } //2
		$a_01_3 = {61 66 66 5f 25 75 2e 64 6c 6c 00 } //1
		$a_01_4 = {73 65 74 75 70 25 75 2e 6c 6e 6b 00 } //1
		$a_01_5 = {53 ff d7 33 d2 6a 19 59 f7 f1 8b 45 08 8b 4d fc 80 c2 61 ff 45 fc 88 14 01 8d 46 01 39 45 fc } //3
		$a_03_6 = {8a 10 40 84 d2 75 ?? 2b c1 83 c0 5c 83 7d 7c 00 68 04 01 00 00 } //1
		$a_01_7 = {53 65 6e 64 69 6e 67 20 65 78 70 6c 6f 69 74 20 74 6f 20 25 73 20 66 72 6f 6d 20 25 73 } //1 Sending exploit to %s from %s
		$a_01_8 = {64 6f 77 6e 6c 6f 61 64 65 64 61 76 } //1 downloadedav
		$a_02_9 = {05 00 00 03 10 00 00 00 [0-02] 00 00 01 00 00 00 [0-02] 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*3+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_02_9  & 1)*1) >=6
 
}