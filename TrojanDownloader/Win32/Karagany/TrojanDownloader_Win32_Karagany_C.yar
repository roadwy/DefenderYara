
rule TrojanDownloader_Win32_Karagany_C{
	meta:
		description = "TrojanDownloader:Win32/Karagany.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 3a 5c 66 6c 61 73 68 5c 6f 74 68 65 72 5c 43 2b 2b 5c 4c 69 74 65 4c 6f 61 64 65 72 20 31 2e 31 5c 52 65 6c 65 61 73 65 5c 66 74 70 70 6c 75 67 } //02 00  M:\flash\other\C++\LiteLoader 1.1\Release\ftpplug
		$a_01_1 = {66 74 70 70 6c 75 67 32 2e 64 6c 6c 00 3f 49 6e 69 74 } //01 00  瑦灰畬㉧搮汬㼀湉瑩
		$a_03_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4f 70 65 72 61 2f 90 10 02 00 2e 90 0f 02 00 20 50 90 03 00 01 72 65 73 74 6f 2f 90 00 } //01 00 
		$a_01_3 = {52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 76 6b 6f 6e 74 61 6b 74 65 2e 72 75 2f 6c 6f 67 69 6e 2e 70 68 70 3f } //00 00  Referer: http://vkontakte.ru/login.php?
	condition:
		any of ($a_*)
 
}