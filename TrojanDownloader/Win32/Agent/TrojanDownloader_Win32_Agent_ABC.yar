
rule TrojanDownloader_Win32_Agent_ABC{
	meta:
		description = "TrojanDownloader:Win32/Agent.ABC,SIGNATURE_TYPE_PEHSTR_EXT,ffffffa5 00 ffffffa4 00 10 00 00 64 00 "
		
	strings :
		$a_00_0 = {8b 45 f4 33 45 f0 33 f0 3b f7 } //0a 00 
		$a_00_1 = {72 61 42 33 47 25 70 } //0a 00  raB3G%p
		$a_00_2 = {73 74 61 74 75 73 3d 73 6c 65 65 70 } //0a 00  status=sleep
		$a_00_3 = {5c 5c 2e 5c 70 69 70 65 5c 24 25 64 24 } //0a 00  \\.\pipe\$%d$
		$a_00_4 = {49 6e 74 65 72 6e 65 74 43 6f 6e 6e 65 63 74 41 } //0a 00  InternetConnectA
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 41 } //0a 00  InternetOpenA
		$a_01_6 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //01 00  InternetReadFile
		$a_00_7 = {66 74 70 3a 2f 2f } //01 00  ftp://
		$a_00_8 = {68 74 74 70 73 3a 2f 2f } //01 00  https://
		$a_00_9 = {68 74 74 70 3a 2f 2f } //01 00  http://
		$a_00_10 = {55 72 6c 43 6f 6f 6b 69 65 53 74 72 } //01 00  UrlCookieStr
		$a_00_11 = {55 72 6c 4e 6f 4c 6f 61 64 } //01 00  UrlNoLoad
		$a_00_12 = {42 36 34 44 65 63 6f 64 65 } //01 00  B64Decode
		$a_00_13 = {42 36 34 45 6e 63 6f 64 65 } //01 00  B64Encode
		$a_00_14 = {42 69 6e 54 6f 53 74 72 } //01 00  BinToStr
		$a_00_15 = {47 65 63 6b 6f 2f 32 30 30 37 30 33 30 39 20 46 69 72 65 66 6f 78 2f 32 2e 30 2e 30 2e 33 } //00 00  Gecko/20070309 Firefox/2.0.0.3
	condition:
		any of ($a_*)
 
}