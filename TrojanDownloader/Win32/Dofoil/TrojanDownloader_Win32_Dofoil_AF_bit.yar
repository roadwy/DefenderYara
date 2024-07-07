
rule TrojanDownloader_Win32_Dofoil_AF_bit{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AF!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 75 06 74 04 90 01 04 5b eb 90 00 } //1
		$a_03_1 = {0f b6 40 02 eb 90 01 02 40 eb 90 01 05 b9 90 01 04 eb 90 01 05 eb 90 01 02 eb 90 01 02 f7 e1 eb 90 01 06 01 d8 74 07 75 05 90 01 05 50 c3 90 00 } //1
		$a_01_2 = {89 ce 83 e6 03 75 0c 8b 5d 10 66 01 da c1 ca 03 89 55 10 30 10 40 c1 ca 08 e2 e4 } //1
		$a_01_3 = {8a 10 80 ca 60 01 d3 d1 e3 03 45 10 8a 08 84 c9 e0 ee } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}