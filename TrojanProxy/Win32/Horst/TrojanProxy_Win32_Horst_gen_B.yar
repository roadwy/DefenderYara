
rule TrojanProxy_Win32_Horst_gen_B{
	meta:
		description = "TrojanProxy:Win32/Horst.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {8b c1 8b 88 00 08 00 00 33 d2 85 c9 7e 11 8b ff 80 34 02 07 8b 88 00 08 00 00 42 3b d1 7c f1 c3 } //3
		$a_01_1 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //1 InternetOpenA
		$a_00_4 = {47 65 74 50 72 6f 63 65 73 73 50 72 69 6f 72 69 74 79 42 6f 6f 73 74 } //1 GetProcessPriorityBoost
		$a_00_5 = {47 65 74 50 72 6f 63 65 73 73 53 68 75 74 64 6f 77 6e 50 61 72 61 6d 65 74 65 72 73 } //1 GetProcessShutdownParameters
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}