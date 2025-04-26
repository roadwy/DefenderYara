
rule TrojanDownloader_Win32_Renos_KN{
	meta:
		description = "TrojanDownloader:Win32/Renos.KN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {3c 75 72 6c 20 67 65 74 3d 22 6f 6e 22 20 63 72 79 70 74 3d 22 6f 6e 22 3e 3c 21 5b 43 44 41 54 41 5b 68 74 74 70 3a 2f 2f } //1 <url get="on" crypt="on"><![CDATA[http://
		$a_00_1 = {3c 75 72 6c 20 70 6f 73 74 3d 22 6f 6e 22 20 63 72 79 70 74 3d 22 6f 6e 22 3e 3c 21 5b 43 44 41 54 41 5b 68 74 74 70 3a 2f 2f } //1 <url post="on" crypt="on"><![CDATA[http://
		$a_01_2 = {53 53 48 4e 41 53 } //1 SSHNAS
		$a_00_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 2c 41 74 74 61 63 68 43 6f 6e 73 6f 6c 65 41 } //1 rundll32.exe C:\Windows\iexplore.exe,AttachConsoleA
		$a_00_4 = {4c 6f 73 41 6c 61 6d 6f 73 00 } //1 潌䅳慬潭s
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}