
rule Trojan_BAT_SpySnake_MAZ_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {57 95 a2 3d 09 03 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9f 00 00 00 27 00 00 00 61 02 } //1
		$a_01_1 = {63 32 64 39 39 34 39 64 2d 64 39 62 61 2d 34 36 61 65 2d 38 34 36 38 2d 36 61 64 30 63 33 35 62 39 34 33 63 } //1 c2d9949d-d9ba-46ae-8468-6ad0c35b943c
		$a_01_2 = {4a 61 6d 62 6f } //1 Jambo
		$a_01_3 = {74 78 74 4c 6f 67 69 6e 5f 4b 65 79 50 72 65 73 73 } //1 txtLogin_KeyPress
		$a_01_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_5 = {74 61 62 43 6f 6e 74 72 6f 6c 31 } //1 tabControl1
		$a_01_6 = {47 65 74 45 78 63 65 6c 50 72 6f 63 65 73 73 41 6e 64 4b 69 6c 6c } //1 GetExcelProcessAndKill
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}