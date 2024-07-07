
rule Trojan_Win32_Picrosia_C{
	meta:
		description = "Trojan:Win32/Picrosia.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b c1 83 e8 20 0f b7 d7 8b ca 33 d2 f7 f1 66 f7 ef 66 05 ef 00 66 25 00 ff 66 83 c0 30 66 89 43 ea 83 c3 20 4e 0f 85 2d ff ff ff } //1
		$a_01_1 = {2f 00 77 00 69 00 6e 00 5f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2f 00 } //1 /win_downloader/windows/
		$a_01_2 = {2f 00 43 00 20 00 74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 20 00 3e 00 } //1 /C tasklist >
		$a_01_3 = {6b 00 69 00 6c 00 6c 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 } //1 kill_process
		$a_01_4 = {72 00 75 00 6e 00 5f 00 70 00 61 00 74 00 63 00 68 00 } //1 run_patch
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}