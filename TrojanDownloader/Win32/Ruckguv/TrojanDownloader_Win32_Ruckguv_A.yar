
rule TrojanDownloader_Win32_Ruckguv_A{
	meta:
		description = "TrojanDownloader:Win32/Ruckguv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f be c9 c1 c0 07 33 c1 42 8a 0a 84 c9 75 f1 } //1
		$a_01_1 = {c6 00 68 89 48 01 c6 40 05 c3 } //1
		$a_01_2 = {25 73 5c 57 69 6e 64 6f 77 73 44 72 69 76 65 72 5f 25 64 2e 65 78 65 } //1 %s\WindowsDriver_%d.exe
		$a_01_3 = {75 67 67 63 3a 2f 2f } //1 uggc://
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}