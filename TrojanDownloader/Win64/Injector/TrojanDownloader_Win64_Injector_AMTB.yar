
rule TrojanDownloader_Win64_Injector_AMTB{
	meta:
		description = "TrojanDownloader:Win64/Injector!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 6f 77 6e 6c 6f 61 64 53 68 65 6c 6c 63 6f 64 65 41 73 79 6e 63 } //DownloadShellcodeAsync  1
		$a_80_1 = {45 78 65 63 75 74 65 53 68 65 6c 6c 63 6f 64 65 } //ExecuteShellcode  1
		$a_80_2 = {53 68 65 6c 6c 63 6f 64 65 44 65 6c 65 67 61 74 65 } //ShellcodeDelegate  1
		$a_80_3 = {53 68 65 6c 6c 63 6f 64 65 4c 6f 61 64 65 72 } //ShellcodeLoader  1
		$a_80_4 = {68 74 74 70 73 3a 2f 2f 63 73 72 73 73 2e 6e 65 74 6c 69 66 79 2e 61 70 70 2f 73 68 65 6c 6c 63 6f 64 65 2e 62 69 6e } //https://csrss.netlify.app/shellcode.bin  1
		$a_80_5 = {35 53 68 65 6c 6c 63 6f 64 65 4c 6f 61 64 65 72 2e 50 72 6f 67 72 61 6d 2b 3c 44 6f 77 6e 6c 6f 61 64 53 68 65 6c 6c 63 6f 64 65 41 73 79 6e 63 3e 64 5f 5f 31 30 } //5ShellcodeLoader.Program+<DownloadShellcodeAsync>d__10  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}