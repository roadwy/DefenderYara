
rule Trojan_Win32_Thewn_A{
	meta:
		description = "Trojan:Win32/Thewn.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {25 32 30 3d 29 26 4e 6f 6d 65 3d 4f 49 45 55 26 44 65 3d 69 70 40 7a 69 70 2e 63 6f 6d 26 50 61 72 61 3d 6a 61 63 68 31 30 39 30 40 67 6d 61 69 6c 2e 63 6f 6d } //1 %20=)&Nome=OIEU&De=ip@zip.com&Para=jach1090@gmail.com
		$a_00_1 = {5c 73 76 68 6f 73 74 73 73 2e 65 78 65 } //1 \svhostss.exe
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 70 69 72 61 6d 2e 63 6f 6d 2e 62 72 2f 68 6f 73 74 73 2e 74 78 74 } //1 http://www.piram.com.br/hosts.txt
		$a_01_3 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}