
rule TrojanProxy_Win32_Xorpix_gen_A{
	meta:
		description = "TrojanProxy:Win32/Xorpix.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 07 00 00 "
		
	strings :
		$a_00_0 = {25 73 77 6f 72 6b 2e 70 68 70 3f 6d 65 74 68 6f 64 3d 75 70 64 61 74 65 26 69 64 3d 25 73 } //2 %swork.php?method=update&id=%s
		$a_00_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_2 = {25 73 77 6f 72 6b 2e 70 68 70 3f 6d 65 74 68 6f 64 3d 67 65 74 26 70 6f 72 74 3d 25 6c 75 26 69 64 3d 25 6c 75 26 74 79 70 65 3d 25 6c 75 26 77 69 6e 76 65 72 3d 25 73 } //2 %swork.php?method=get&port=%lu&id=%lu&type=%lu&winver=%s
		$a_00_3 = {6d 61 69 6e 5f 62 74 } //1 main_bt
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_5 = {73 6f 63 6b 65 74 } //1 socket
		$a_00_6 = {69 6e 65 74 5f 61 64 64 72 } //1 inet_addr
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}