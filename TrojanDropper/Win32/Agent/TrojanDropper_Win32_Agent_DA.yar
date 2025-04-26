
rule TrojanDropper_Win32_Agent_DA{
	meta:
		description = "TrojanDropper:Win32/Agent.DA,SIGNATURE_TYPE_PEHSTR,ffffff8d 00 ffffff8d 00 06 00 00 "
		
	strings :
		$a_01_0 = {c7 45 9c 41 41 41 41 c7 45 a0 41 41 41 41 } //100
		$a_01_1 = {63 6c 65 66 64 65 6e 63 72 79 70 74 69 6f 6e } //10 clefdencryption
		$a_01_2 = {2d 4c 49 42 47 43 43 57 33 32 2d 45 48 2d 32 2d 53 4a 4c 4a 2d 47 54 48 52 2d 4d 49 4e 47 57 33 32 } //10 -LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32
		$a_01_3 = {5c 73 70 6f 6f 6c 73 72 2e 65 78 65 } //10 \spoolsr.exe
		$a_01_4 = {5c 53 59 53 54 45 4d 33 32 5c 73 70 6f 6f 6c 73 72 2e 65 78 65 } //10 \SYSTEM32\spoolsr.exe
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1) >=141
 
}