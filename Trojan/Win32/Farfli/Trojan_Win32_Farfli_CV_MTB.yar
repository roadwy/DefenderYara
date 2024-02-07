
rule Trojan_Win32_Farfli_CV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 57 69 6e 64 6f 77 73 38 38 2e 65 78 65 } //01 00  C:Windows88.exe
		$a_01_1 = {32 30 33 2e 31 36 30 2e 35 34 2e 32 35 30 2f 39 } //01 00  203.160.54.250/9
		$a_01_2 = {40 66 75 63 6b } //01 00  @fuck
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_CV_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.CV!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 50 6a eb 01 40 27 80 38 e8 30 04 c6 cc 1a 48 16 5c f6 f7 7c 40 01 07 0f b6 1e 88 18 46 90 34 3e 29 f4 47 25 ec c9 0c 44 24 1c 61 cc 75 60 } //01 00 
		$a_01_1 = {cd 07 ad c1 c8 b0 35 87 36 2a 74 56 75 f2 } //01 00 
		$a_01_2 = {67 42 a2 e4 28 22 69 32 4d 14 1b 44 e8 8d 35 9d 17 19 0b 43 dc 34 9c 7f 03 } //00 00 
	condition:
		any of ($a_*)
 
}