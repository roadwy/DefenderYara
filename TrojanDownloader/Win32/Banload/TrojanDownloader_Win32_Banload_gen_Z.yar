
rule TrojanDownloader_Win32_Banload_gen_Z{
	meta:
		description = "TrojanDownloader:Win32/Banload.gen!Z,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {eb 05 be 01 00 00 00 a1 90 01 04 33 db 8a 5c 30 ff 33 5d e8 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 d4 8b d3 e8 90 00 } //5
		$a_03_1 = {c6 00 01 b1 01 b2 01 a1 90 01 04 e8 90 01 04 8b 90 01 04 90 01 01 89 02 a1 90 01 04 8b 00 c6 40 0f 01 a1 90 01 04 8b 00 e8 90 01 04 eb 0a 68 e8 03 00 00 e8 90 00 } //1
		$a_03_2 = {ff 75 d8 ff 75 ec 8d 55 d4 b8 90 01 04 e8 90 01 04 ff 75 d4 8d 45 dc ba 03 00 00 00 e8 90 01 04 8b 45 dc e8 90 01 04 50 e8 90 00 } //1
		$a_03_3 = {ff 75 d8 8d 55 d4 b8 90 01 04 e8 90 01 04 ff 75 d4 8d 45 e0 ba 04 00 00 00 e8 90 01 04 8b 45 e0 e8 90 01 04 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=7
 
}