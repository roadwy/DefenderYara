
rule Trojan_Win32_AppleJeus_A{
	meta:
		description = "Trojan:Win32/AppleJeus.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {5a 3a 5c 6a 65 75 73 5c 64 6f 77 6e 6c 6f 61 64 65 72 5c 64 6f 77 6e 6c 6f 61 64 65 72 5f 65 78 65 5f 76 73 32 30 31 30 5c 52 65 6c 65 61 73 65 5c 64 6c 6f 61 64 65 72 2e 70 64 62 } //3 Z:\jeus\downloader\downloader_exe_vs2010\Release\dloader.pdb
		$a_01_1 = {c7 44 24 64 68 74 74 70 c7 44 24 68 73 3a 2f 2f c7 44 24 6c 77 77 77 2e c6 44 24 70 63 88 5c 24 71 c7 44 24 72 6c 61 73 6c } //3
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}