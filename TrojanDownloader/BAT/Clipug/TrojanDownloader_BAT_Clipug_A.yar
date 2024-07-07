
rule TrojanDownloader_BAT_Clipug_A{
	meta:
		description = "TrojanDownloader:BAT/Clipug.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 42 20 5a 20 6e 65 74 61 5c 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 5c 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 70 64 62 } //1 VB Z neta\WindowsApplication1\WindowsApplication1\obj\x86\Debug\WindowsApplication1.pdb
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 6c 00 75 00 7a 00 62 00 79 00 2d 00 73 00 70 00 65 00 63 00 6a 00 61 00 6c 00 6e 00 65 00 2e 00 63 00 62 00 61 00 2e 00 70 00 6c 00 2f 00 6e 00 72 00 32 00 36 00 2e 00 74 00 78 00 74 00 } //1 http://sluzby-specjalne.cba.pl/nr26.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}