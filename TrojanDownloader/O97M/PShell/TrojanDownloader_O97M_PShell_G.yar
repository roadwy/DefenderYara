
rule TrojanDownloader_O97M_PShell_G{
	meta:
		description = "TrojanDownloader:O97M/PShell.G,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("Wscript.Shell")
		$a_00_1 = {2e 52 65 67 57 72 69 74 65 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c 55 70 64 61 74 22 2c 20 22 77 73 63 72 69 70 74 } //1 .RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updat", "wscript
		$a_02_2 = {45 6e 76 69 72 6f 6e 24 28 22 55 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 22 90 02 20 5c 53 69 6c 65 6e 74 2e 76 62 73 22 2c 20 22 52 45 47 5f 53 5a 22 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}