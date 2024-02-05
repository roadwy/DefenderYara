
rule Trojan_Win32_Downloader_GA_MTB{
	meta:
		description = "Trojan:Win32/Downloader.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 0a 00 "
		
	strings :
		$a_80_0 = {5c 42 65 61 6d 57 69 6e 48 54 54 50 32 5c 52 65 6c 65 61 73 65 5c 42 65 61 6d 57 69 6e 48 54 54 50 2e 70 64 62 } //\BeamWinHTTP2\Release\BeamWinHTTP.pdb  0a 00 
		$a_80_1 = {5c 42 65 61 6d 57 69 6e 48 54 54 50 5c 52 65 6c 65 61 73 65 5c 42 65 61 6d 57 69 6e 48 54 54 50 2e 70 64 62 } //\BeamWinHTTP\Release\BeamWinHTTP.pdb  01 00 
		$a_80_2 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 72 75 2d 52 55 2c 72 75 } //Accept-Language: ru-RU,ru  01 00 
		$a_80_3 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } ///c taskkill /im  01 00 
		$a_80_4 = {2f 63 20 73 74 61 72 74 20 2f 49 } ///c start /I  01 00 
		$a_80_5 = {69 70 6c 6f 67 67 65 72 2e 6f 72 67 } //iplogger.org  00 00 
	condition:
		any of ($a_*)
 
}