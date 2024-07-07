
rule Trojan_Win32_CryptInject_PI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 78 00 78 00 78 00 74 00 6f 00 6f 00 6c 00 62 00 61 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 5f 00 73 00 74 00 72 00 61 00 69 00 67 00 68 00 74 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 http://install.xxxtoolbar.com/download_straight.html
		$a_01_1 = {67 6f 69 63 66 62 6f 6f 67 69 64 69 6b 6b 65 6a 63 63 6d 63 6c 70 69 65 69 63 69 68 68 6c 70 6f 20 62 69 68 67 62 70 } //1 goicfboogidikkejccmclpieicihhlpo bihgbp
		$a_01_2 = {67 6f 69 63 66 62 6f 6f 67 69 64 69 6b 6b 65 6a 63 63 6d 63 6c 70 69 65 69 63 69 68 68 6c 70 6f 20 65 6a 65 6d 64 6e } //1 goicfboogidikkejccmclpieicihhlpo ejemdn
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 4d 61 70 5c 44 6f 6d 61 69 6e 73 5c 78 78 78 74 6f 6f 6c 62 61 72 2e 63 6f 6d } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\xxxtoolbar.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_CryptInject_PI_MTB_2{
	meta:
		description = "Trojan:Win32/CryptInject.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 57 a1 90 01 03 00 a3 90 01 03 00 8b 0d 90 01 03 00 89 0d 90 01 03 00 8b 15 90 01 03 00 8b 02 a3 90 01 03 00 8b 0d 90 01 03 00 81 e9 fc 1a 01 00 89 0d 90 01 03 00 8b 0d 90 01 03 00 81 c1 fc 1a 01 00 a1 90 01 03 00 a3 90 01 03 00 90 08 00 03 a1 90 01 03 00 31 0d 90 01 03 00 90 02 a0 8b ff c7 05 90 01 03 00 00 00 00 00 a1 90 01 03 00 01 05 90 01 03 00 8b ff 8b 15 90 01 03 00 a1 90 01 03 00 89 02 5f 5d c3 90 00 } //10
		$a_02_1 = {55 8b ec 53 57 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 8b 02 a3 90 01 04 8b 0d 90 01 04 81 e9 90 01 04 89 0d 90 01 04 8b 0d 90 01 04 81 c1 90 01 04 a1 90 01 04 a3 90 01 04 90 08 00 03 a1 90 01 04 33 c1 90 08 00 03 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 15 90 01 04 a1 90 01 04 89 02 90 00 } //10
		$a_00_2 = {8b 4d fc 8d 94 01 36 a6 06 00 8b 45 08 03 10 8b 4d 08 89 11 8b 55 08 8b 02 2d 36 a6 06 00 8b 4d 08 89 01 } //1
		$a_00_3 = {8b 55 08 03 32 8b 45 08 89 30 8b 4d 08 8b 11 81 ea 36 a6 06 00 8b 45 08 89 10 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=11
 
}