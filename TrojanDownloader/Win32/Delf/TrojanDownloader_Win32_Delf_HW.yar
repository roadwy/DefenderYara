
rule TrojanDownloader_Win32_Delf_HW{
	meta:
		description = "TrojanDownloader:Win32/Delf.HW,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 70 6c 75 73 62 61 67 } //03 00  \SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\plusbag
		$a_01_1 = {5c 41 70 70 20 4d 61 6e 61 67 65 6d 65 6e 74 5c 41 52 50 43 61 63 68 65 5c 70 6c 75 73 62 61 67 } //05 00  \App Management\ARPCache\plusbag
		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 70 6c 75 73 62 61 67 2e 6e 65 74 2f 63 6f 75 6e 74 2f 69 6e 73 74 61 6c 6c 5f 63 6f 75 6e 74 2e 70 68 70 3f 70 69 64 3d } //05 00  http://www.plusbag.net/count/install_count.php?pid=
		$a_01_3 = {77 69 6e 64 6f 77 73 20 70 6c 75 73 62 61 67 } //00 00  windows plusbag
	condition:
		any of ($a_*)
 
}