
rule TrojanDownloader_Win32_Renos_IT{
	meta:
		description = "TrojanDownloader:Win32/Renos.IT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 04 3e 46 eb 90 09 05 00 35 ?? 00 00 00 } //1
		$a_01_1 = {68 ff ff 0d ba ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Renos_IT_2{
	meta:
		description = "TrojanDownloader:Win32/Renos.IT,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 02 66 2b c0 c1 c2 19 b9 08 ef bf ff f7 d1 e8 } //1
		$a_01_1 = {8b 39 c1 f2 15 66 83 c1 33 83 c0 01 c1 c6 09 8b 08 f7 d2 29 f9 75 ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}