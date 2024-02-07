
rule Trojan_Win32_Chepdu_D{
	meta:
		description = "Trojan:Win32/Chepdu.D,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 50 45 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //0a 00 
		$a_01_1 = {00 58 4d 4c 32 } //02 00 
		$a_01_2 = {25 73 75 73 65 72 69 6e 69 74 7c 25 73 7c 25 73 } //02 00  %suserinit|%s|%s
		$a_01_3 = {72 65 67 73 76 72 33 32 2e 65 78 65 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00 
		$a_01_4 = {43 6f 49 6e 74 65 72 6e 65 74 43 6f 6d 70 61 72 65 55 72 6c } //01 00  CoInternetCompareUrl
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 27 } //01 00  URLDownloadToFileA'
		$a_01_6 = {71 3d 00 73 65 61 72 63 68 3f } //00 00  㵱猀慥捲㽨
	condition:
		any of ($a_*)
 
}