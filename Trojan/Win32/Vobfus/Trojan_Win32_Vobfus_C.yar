
rule Trojan_Win32_Vobfus_C{
	meta:
		description = "Trojan:Win32/Vobfus.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 } //1 taskkill /im
		$a_01_1 = {44 3a 5c 53 44 5f 47 45 4e 5c 64 6f 77 6e 6c 6f 61 64 65 72 5c 64 6f 77 6e 6c 6f 61 64 65 72 67 67 5c 76 62 36 5c 56 42 36 2e 4f 4c 42 } //2 D:\SD_GEN\downloader\downloadergg\vb6\VB6.OLB
		$a_01_2 = {42 6c 6f 63 6b 44 65 63 72 79 70 74 } //2 BlockDecrypt
		$a_01_3 = {76 62 65 78 65 4c 69 73 74 31 } //1 vbexeList1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=6
 
}