
rule TrojanDownloader_Win32_BrobanKew_A{
	meta:
		description = "TrojanDownloader:Win32/BrobanKew.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 49 75 f9 53 bb 90 01 04 33 c0 55 68 90 01 04 64 ff 30 64 89 20 8d 55 fc b8 90 01 04 e8 90 01 04 8b 55 fc 8b c3 e8 90 01 04 8d 55 f8 b8 90 01 04 e8 90 01 04 8b 55 f8 8d 43 04 e8 90 01 04 8d 55 f4 b8 90 01 04 e8 90 01 04 8b 55 f4 8d 43 08 e8 90 01 04 8d 55 f0 b8 90 01 04 e8 90 01 04 8b 55 f0 8d 43 0c e8 90 01 04 8d 55 ec b8 90 01 04 e8 90 01 04 8b 55 ec 8d 43 10 e8 90 01 04 8d 55 e8 90 00 } //1
		$a_03_1 = {e9 21 01 00 00 8d 45 f4 ba 90 01 04 e8 90 01 04 8d 45 f8 33 d2 e8 90 01 04 8b 45 f4 85 c0 74 16 90 00 } //1
		$a_03_2 = {64 89 20 8d 45 d8 e8 90 01 04 8b 45 d8 8b 15 90 01 04 90 02 03 e8 90 01 04 75 09 e8 90 01 04 84 c0 74 21 a1 90 01 04 8b 00 e8 90 01 04 33 c0 5a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}