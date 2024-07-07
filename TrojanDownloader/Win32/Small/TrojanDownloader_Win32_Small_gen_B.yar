
rule TrojanDownloader_Win32_Small_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Small.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 73 68 65 6c 00 6b 6c 6f 70 } //1
		$a_00_1 = {75 72 6c 6d 6f 6e 2e 64 6c 6c 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 63 3a 5c 74 73 6b 6d 67 72 2e 65 78 65 } //1
		$a_02_2 = {2e 63 6f 6d 90 02 03 2f 32 2e 65 78 65 90 00 } //1
		$a_00_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}