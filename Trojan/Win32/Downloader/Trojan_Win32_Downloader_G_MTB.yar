
rule Trojan_Win32_Downloader_G_MTB{
	meta:
		description = "Trojan:Win32/Downloader.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {5c 42 65 61 6d 57 69 6e 48 54 54 50 32 5c 52 65 6c 65 61 73 65 5c 42 65 61 6d 57 69 6e 48 54 54 50 2e 70 64 62 } //\BeamWinHTTP2\Release\BeamWinHTTP.pdb  1
		$a_80_1 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 72 75 2d 52 55 2c 72 75 } //Accept-Language: ru-RU,ru  1
		$a_80_2 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } ///c taskkill /im  1
		$a_80_3 = {2f 63 20 73 74 61 72 74 20 2f 49 } ///c start /I  1
		$a_80_4 = {63 6f 75 6e 74 72 79 5f 63 6f 64 65 } //country_code  1
		$a_80_5 = {69 70 6c 6f 67 67 65 72 2e 6f 72 67 } //iplogger.org  1
		$a_80_6 = {2f 73 75 63 63 65 73 73 } ///success  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}