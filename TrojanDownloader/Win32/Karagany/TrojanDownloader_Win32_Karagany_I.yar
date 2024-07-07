
rule TrojanDownloader_Win32_Karagany_I{
	meta:
		description = "TrojanDownloader:Win32/Karagany.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 68 6f 77 74 68 72 65 61 64 2e 70 68 70 3f 74 3d } //2 showthread.php?t=
		$a_00_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 2d 6e 20 31 20 2d 77 } //1 cmd.exe /c ping -n 1 -w
		$a_01_2 = {80 3f 6b 74 07 80 3f 4b 74 02 eb e9 5f } //2
		$a_03_3 = {2a 00 00 00 eb 09 8b 55 90 01 01 83 c2 01 89 55 90 01 01 83 7d 90 01 01 2f 73 21 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*1) >=4
 
}