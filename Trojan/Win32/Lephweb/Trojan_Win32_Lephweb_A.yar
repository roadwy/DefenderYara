
rule Trojan_Win32_Lephweb_A{
	meta:
		description = "Trojan:Win32/Lephweb.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 20 77 65 62 68 65 6c 70 2e 65 78 65 } //1 Explorer.exe webhelp.exe
		$a_01_1 = {77 65 62 73 68 6f 77 2e 64 6c 6c 00 } //1
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_01_3 = {3a 5c 74 65 73 74 2e 74 78 74 2e 70 6f 70 } //1 :\test.txt.pop
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}