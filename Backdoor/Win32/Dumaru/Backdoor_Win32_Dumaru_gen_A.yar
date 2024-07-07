
rule Backdoor_Win32_Dumaru_gen_A{
	meta:
		description = "Backdoor:Win32/Dumaru.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 74 74 70 53 65 6e 64 52 65 71 75 65 73 74 41 } //1 HttpSendRequestA
		$a_01_1 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_2 = {5c 64 76 70 2e 6c 6f 67 } //1 \dvp.log
		$a_00_3 = {5c 53 59 53 54 45 4d 33 32 5c 44 52 49 56 45 52 53 5c 45 54 43 5c 68 6f 73 74 73 } //1 \SYSTEM32\DRIVERS\ETC\hosts
		$a_01_4 = {56 6f 6c 6b 2c 20 65 69 6e 20 52 45 49 43 48 2c 20 65 69 6e 20 46 75 68 72 65 72 20 21 21 21 } //1 Volk, ein REICH, ein Fuhrer !!!
		$a_01_5 = {64 76 70 64 2e 44 4c 4c 00 4d 48 6f 6f 6b 00 4d 55 6e 48 6f 6f 6b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}