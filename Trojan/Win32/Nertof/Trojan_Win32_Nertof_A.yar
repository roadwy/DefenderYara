
rule Trojan_Win32_Nertof_A{
	meta:
		description = "Trojan:Win32/Nertof.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {31 00 38 00 35 00 2e 00 31 00 34 00 2e 00 31 00 38 00 35 00 2e 00 33 00 38 00 2f 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2f 00 70 00 6f 00 69 00 6e 00 74 00 2e 00 70 00 68 00 70 00 } //1 185.14.185.38/google/point.php
		$a_01_1 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 66 00 69 00 6c 00 65 00 28 00 27 00 31 00 4c 00 31 00 27 00 2c 00 27 00 31 00 46 00 31 00 27 00 29 00 3b 00 73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 31 00 43 00 31 00 } //1 downloadfile('1L1','1F1');start-process rundll32.exe "1C1
		$a_01_2 = {32 00 3d 00 42 00 6f 00 54 00 } //1 2=BoT
		$a_01_3 = {5b 00 50 00 41 00 53 00 53 00 57 00 20 00 46 00 49 00 4c 00 45 00 53 00 5d 00 } //1 [PASSW FILES]
		$a_01_4 = {5b 00 48 00 55 00 4e 00 54 00 45 00 52 00 20 00 46 00 49 00 4c 00 45 00 53 00 5d 00 } //1 [HUNTER FILES]
		$a_01_5 = {30 00 3d 00 31 00 30 00 32 00 30 00 33 00 30 00 40 00 40 00 23 00 23 00 23 00 23 00 23 00 } //1 0=102030@@#####
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}