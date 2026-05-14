
rule DoS_Win64_RumbleBread_A_dha{
	meta:
		description = "DoS:Win64/RumbleBread.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_01_1 = {43 3a 5c 5c 57 69 6e 64 6f 77 73 7c 43 3a 5c 5c 55 73 65 72 73 7c 43 3a 5c 5c 50 72 6f 67 72 61 6d 44 61 74 61 } //1 C:\\Windows|C:\\Users|C:\\ProgramData
		$a_01_2 = {53 79 6d 61 6e 74 65 63 7c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 7c 45 53 45 54 7c 6d 69 63 72 6f 73 6f 66 74 20 73 68 61 72 65 64 7c 57 69 6e 64 6f 77 73 20 4e 54 7c 41 70 70 44 61 74 61 7c 4d 69 63 72 6f 73 6f 66 74 5c 5c 57 69 6e 64 6f 77 73 41 70 70 73 7c 64 65 73 6b 74 6f 70 2e 69 6e 69 } //1 Symantec|Windows Defender|ESET|microsoft shared|Windows NT|AppData|Microsoft\\WindowsApps|desktop.ini
		$a_01_3 = {2f 57 69 6e 64 6f 77 73 2f 74 77 61 69 6e 5f 33 32 2e 62 61 74 } //2 /Windows/twain_32.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}