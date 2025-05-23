
rule PWS_Win32_Yahoopass_H{
	meta:
		description = "PWS:Win32/Yahoopass.H,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 6c 61 63 69 61 6c 20 44 72 61 63 6f 6e 00 00 2d 00 00 00 25 73 } //2
		$a_03_1 = {65 6d 62 65 64 64 69 6e 67 [0-02] 73 6f 6c [0-04] 73 68 75 74 64 6f 77 6e [0-04] 2d 73 } //2
		$a_03_2 = {25 53 59 53 54 45 4d 52 4f 4f 54 25 [0-02] 2f 46 20 63 3a 5c 2a 2e 2a [0-04] 64 65 6c 20 2f 41 3a 53 20 2f 51 20 [0-04] 63 3a 5c 6e 74 6c 64 72 2e 62 61 74 } //2
		$a_03_3 = {61 2e 30 36 [0-02] 67 6f 6f 67 6c 65 [0-03] 2e 64 6c 6c [0-04] 5c 67 6f 6f 67 6c 65 3f 3f 2e 64 6c 6c } //2
		$a_00_4 = {68 00 00 00 40 05 60 01 00 00 50 ff 15 ac 10 80 67 8b d8 83 fb ff 74 4e 39 75 f0 74 42 56 8d 45 0c 50 ff 75 e8 e8 bb 03 00 00 8b 35 58 10 80 67 59 40 50 ff 75 e8 53 ff d6 8b 7d ec 2b 7d f0 68 40 12 80 67 57 ff 75 f0 e8 61 11 00 00 83 c4 0c 6a 00 8d 45 0c 50 57 ff 75 f0 53 ff d6 33 f6 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_00_4  & 1)*2) >=8
 
}