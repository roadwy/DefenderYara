
rule TrojanDownloader_Win64_Blouiroet_SK_MTB{
	meta:
		description = "TrojanDownloader:Win64/Blouiroet.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 74 65 6d 70 36 2e 65 78 65 } //02 00  c:\programdata\temp6.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 69 6e 68 6f 73 74 2e 78 79 7a 2f 75 70 64 61 74 65 2f 75 70 64 61 74 65 2e 72 61 72 } //02 00  http://winhost.xyz/update/update.rar
		$a_01_2 = {68 74 74 70 3a 2f 2f 66 6f 6e 74 64 72 76 68 6f 73 74 2e 78 79 7a 2f 75 70 64 61 74 65 2f 74 65 73 74 35 2e 72 61 72 } //01 00  http://fontdrvhost.xyz/update/test5.rar
		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //01 00  InternetOpenUrlA
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //00 00  InternetReadFile
	condition:
		any of ($a_*)
 
}