
rule TrojanDownloader_Win32_Delf_UZ{
	meta:
		description = "TrojanDownloader:Win32/Delf.UZ,SIGNATURE_TYPE_PEHSTR,18 00 18 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {6e 65 74 73 68 2e 65 78 65 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 22 20 41 4e 54 54 54 20 45 4e 41 42 4c 45 } //01 00  netsh.exe firewall add allowedprogram "C:\myapp.exe" ANTTT ENABLE
		$a_01_2 = {55 53 45 52 20 25 73 40 25 73 40 25 73 } //01 00  USER %s@%s@%s
		$a_01_3 = {77 77 77 2e 73 72 70 65 2e 6f 72 67 2e 62 72 } //01 00  www.srpe.org.br
		$a_01_4 = {73 72 70 65 37 34 31 35 } //01 00  srpe7415
		$a_01_5 = {69 6d 67 63 61 72 74 61 7a 32 2e 6a 70 67 } //01 00  imgcartaz2.jpg
		$a_01_6 = {63 3a 5c 6d 73 6e 2e 62 63 6b } //01 00  c:\msn.bck
		$a_01_7 = {6d 73 6e 2e 6a 70 67 } //00 00  msn.jpg
	condition:
		any of ($a_*)
 
}