
rule TrojanDownloader_Win32_Zlob_II{
	meta:
		description = "TrojanDownloader:Win32/Zlob.II,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_02_0 = {8d 50 01 8a 08 83 c0 01 84 c9 75 f7 2b c2 56 8b f0 74 0f b0 2f 38 86 ?? ?? ?? ?? 74 0a 83 ee 01 75 f3 } //10
		$a_00_1 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_00_2 = {49 73 42 61 64 57 72 69 74 65 50 74 72 } //1 IsBadWritePtr
		$a_00_3 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_00_4 = {2f 63 6f 6e 66 69 72 6d 2e 70 68 70 3f 61 69 64 3d 25 6c 75 26 73 61 69 64 3d 25 6c 75 26 6d 61 63 3d 25 73 26 6d 6e 3d 25 6c 75 } //1 /confirm.php?aid=%lu&said=%lu&mac=%s&mn=%lu
		$a_00_5 = {2e 63 6f 6d 2f 64 77 2e 70 68 70 } //1 .com/dw.php
		$a_00_6 = {77 69 6e 70 6f 6c 65 33 32 2e 65 78 65 } //1 winpole32.exe
		$a_00_7 = {2f 6d 65 64 69 61 2e 70 68 70 } //1 /media.php
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=15
 
}