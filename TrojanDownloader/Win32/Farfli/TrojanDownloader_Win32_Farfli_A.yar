
rule TrojanDownloader_Win32_Farfli_A{
	meta:
		description = "TrojanDownloader:Win32/Farfli.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 69 6e 66 6f 72 73 } //01 00 
		$a_01_1 = {67 62 77 7c 7b 67 60 7a 3a 71 6c 71 } //01 00 
		$a_01_2 = {c6 45 d8 31 c6 45 d9 14 c6 45 da 59 c6 45 db 29 c6 45 dc 29 c6 45 dd 5a c6 45 de 5d } //01 00 
		$a_03_3 = {8a 04 02 30 01 46 3b 90 03 01 01 74 75 90 02 03 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}