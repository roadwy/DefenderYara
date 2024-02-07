
rule TrojanDownloader_BAT_Balamid_B{
	meta:
		description = "TrojanDownloader:BAT/Balamid.B,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 6e 65 77 2e 65 78 65 } //0a 00  svchostnew.exe
		$a_01_1 = {77 00 77 00 2e 00 77 00 69 00 6e 00 74 00 61 00 73 00 6b 00 31 00 36 00 2e 00 63 00 6f 00 6d 00 2f 00 76 00 32 00 2e 00 74 00 78 00 74 00 } //0a 00  ww.wintask16.com/v2.txt
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 77 00 69 00 6e 00 74 00 61 00 73 00 6b 00 31 00 36 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 78 00 63 00 32 00 2e 00 74 00 78 00 74 00 } //01 00  http://www.wintask16.com/exc2.txt
		$a_01_3 = {5c 00 6c 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //01 00  \lsm.exe
		$a_01_4 = {62 00 61 00 67 00 6c 00 61 00 6e 00 6d 00 61 00 64 00 69 00 } //01 00  baglanmadi
		$a_01_5 = {73 65 74 5f 50 61 73 73 77 6f 72 64 00 73 65 74 5f 55 73 65 72 6e 61 6d 65 } //00 00 
		$a_00_6 = {87 10 00 00 c1 8b 62 34 6e 7c 4f } //69 35 
	condition:
		any of ($a_*)
 
}