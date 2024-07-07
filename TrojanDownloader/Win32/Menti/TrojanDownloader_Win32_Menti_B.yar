
rule TrojanDownloader_Win32_Menti_B{
	meta:
		description = "TrojanDownloader:Win32/Menti.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6a 6f 62 2e 65 78 65 } //1 job.exe
		$a_01_1 = {68 6f 62 2e 65 78 65 } //1 hob.exe
		$a_01_2 = {69 6f 62 2e 65 78 65 } //1 iob.exe
		$a_01_3 = {67 6f 62 2e 65 78 65 } //1 gob.exe
		$a_01_4 = {8b c8 c1 e9 0a 81 e9 00 28 00 00 25 ff 03 00 00 2d 00 24 00 00 66 89 0c 57 66 89 44 57 02 42 42 8b 4d fc 3b 4d 10 0f 85 4c ff ff ff 33 c0 40 8b 4d 08 5e 89 11 5b c9 } //1
		$a_03_5 = {8b 02 8b 0e 8a 0c 08 8a c1 e8 90 01 04 84 c0 75 10 80 f9 3b 75 17 8b c6 e8 90 01 04 84 c0 74 09 ff 06 8b 06 3b 42 04 7c d5 90 00 } //1
		$a_01_6 = {59 be f9 93 04 00 33 db 53 53 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}