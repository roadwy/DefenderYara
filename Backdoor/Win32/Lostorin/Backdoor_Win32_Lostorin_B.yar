
rule Backdoor_Win32_Lostorin_B{
	meta:
		description = "Backdoor:Win32/Lostorin.B,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 20 57 69 6e 21 } //1 You Win!
		$a_01_1 = {50 72 6f 63 65 73 73 20 4b 69 6c 6c 20 4f 4b } //1 Process Kill OK
		$a_01_2 = {6b 65 79 5f 6c 6f 67 20 73 74 61 72 74 } //1 key_log start
		$a_01_3 = {4f 70 65 6e 55 73 65 72 44 65 73 6b 74 6f 70 20 69 73 20 6f 6b } //1 OpenUserDesktop is ok
		$a_01_4 = {6b 65 79 20 68 6f 6f 6b 20 69 73 20 6f 6b } //1 key hook is ok
		$a_01_5 = {43 3a 5c 52 45 43 59 43 4c 45 52 5c 4b 45 59 2d 25 64 2d 25 64 2d 25 64 2e 4c 4f 47 } //1 C:\RECYCLER\KEY-%d-%d-%d.LOG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}