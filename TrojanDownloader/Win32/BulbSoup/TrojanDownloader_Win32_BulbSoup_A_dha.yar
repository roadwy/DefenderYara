
rule TrojanDownloader_Win32_BulbSoup_A_dha{
	meta:
		description = "TrojanDownloader:Win32/BulbSoup.A!dha,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffc8 00 ffffffc8 00 02 00 00 64 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 } //64 00  curl.exe -k
		$a_00_1 = {75 00 66 00 6f 00 77 00 64 00 61 00 75 00 63 00 7a 00 77 00 70 00 61 00 34 00 65 00 6e 00 6d 00 7a 00 6a 00 32 00 79 00 79 00 66 00 37 00 6d 00 34 00 63 00 62 00 73 00 6a 00 63 00 61 00 78 00 78 00 6f 00 79 00 65 00 65 00 62 00 63 00 32 00 77 00 64 00 67 00 7a 00 77 00 6e 00 68 00 76 00 77 00 68 00 6a 00 66 00 37 00 69 00 69 00 64 00 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 } //00 00  ufowdauczwpa4enmzj2yyf7m4cbsjcaxxoyeebc2wdgzwnhvwhjf7iid.onion
	condition:
		any of ($a_*)
 
}