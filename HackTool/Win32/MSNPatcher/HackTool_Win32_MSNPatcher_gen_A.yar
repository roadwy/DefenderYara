
rule HackTool_Win32_MSNPatcher_gen_A{
	meta:
		description = "HackTool:Win32/MSNPatcher.gen!A,SIGNATURE_TYPE_PEHSTR,79 00 6e 00 05 00 00 "
		
	strings :
		$a_01_0 = {3b 7a 14 72 1f 8b 42 14 03 42 10 3b f8 73 15 8b 42 14 2b f8 8b 42 0c 03 c7 8b c8 33 c0 40 5e 5f c9 c2 08 00 } //100
		$a_01_1 = {06 b6 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 4d 53 4e 4d 65 73 73 65 6e 67 65 72 } //10
		$a_01_2 = {4d 53 4e 5c 57 69 6e 64 6f 77 73 20 4d 65 73 73 65 6e 67 65 72 20 55 6e 69 76 65 72 73 61 6c 20 4c 6f 61 64 65 72 } //10 MSN\Windows Messenger Universal Loader
		$a_01_3 = {6a 6e 72 7a 2e 32 6b 7a 6f 6e 65 2e 6e 65 74 } //1 jnrz.2kzone.net
		$a_01_4 = {55 6e 69 76 65 72 73 61 6c 20 4a 6e 72 7a 4c 6f 61 64 65 72 } //1 Universal JnrzLoader
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=110
 
}