
rule TrojanDownloader_Win32_Popal_A{
	meta:
		description = "TrojanDownloader:Win32/Popal.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 50 4f 50 5c 52 65 6c 65 61 73 65 5c 70 6f 70 } //4 D:\POP\Release\pop
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 65 6e 61 6f 6e 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 6f 2f 70 6f 70 33 2e 65 78 65 } //4 http://www.menaon.com/downloo/pop3.exe
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4) >=8
 
}