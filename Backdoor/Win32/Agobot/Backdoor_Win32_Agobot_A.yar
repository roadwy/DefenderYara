
rule Backdoor_Win32_Agobot_A{
	meta:
		description = "Backdoor:Win32/Agobot.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {23 65 6e 63 23 2e 74 6d 70 } //1 #enc#.tmp
		$a_01_1 = {23 65 6e 63 23 25 73 25 73 25 30 38 58 2e 74 6d 70 } //1 #enc#%s%s%08X.tmp
		$a_01_2 = {53 65 6e 64 54 43 50 28 29 3a 20 73 69 64 3d 25 64 } //1 SendTCP(): sid=%d
		$a_01_3 = {53 65 6e 64 54 43 50 28 29 3a 20 53 65 6e 74 20 25 64 20 62 79 74 65 73 } //1 SendTCP(): Sent %d bytes
		$a_01_4 = {53 65 6e 64 54 43 50 28 29 3a 20 47 6f 74 20 25 64 2f 25 64 20 62 79 74 65 73 } //1 SendTCP(): Got %d/%d bytes
		$a_01_5 = {23 65 6e 63 23 4d 69 6e 69 44 75 6d 70 57 72 69 74 65 44 75 6d 70 } //1 #enc#MiniDumpWriteDump
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}