
rule Backdoor_Win32_PcClient_gen_F{
	meta:
		description = "Backdoor:Win32/PcClient.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 05 00 00 "
		
	strings :
		$a_01_0 = {32 32 32 2e 31 31 2e 31 32 2e 32 36 } //5 222.11.12.26
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 74 77 67 79 78 78 2e 63 6f 6d 2f 49 6d 61 67 65 73 2f 62 67 5f 30 36 2e 67 69 66 } //5 http://www.ytwgyxx.com/Images/bg_06.gif
		$a_01_2 = {4d 65 73 73 65 6e 67 65 72 } //5 Messenger
		$a_01_3 = {30 30 30 30 31 38 32 33 } //5 00001823
		$a_01_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 31 2e 65 78 65 } //5 C:\WINDOWS\system32\1.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=25
 
}