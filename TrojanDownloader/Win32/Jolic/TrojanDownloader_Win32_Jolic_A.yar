
rule TrojanDownloader_Win32_Jolic_A{
	meta:
		description = "TrojanDownloader:Win32/Jolic.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {46 3c 23 0f 85 90 01 04 33 c9 eb 90 01 01 ba 5b 5d 00 00 66 39 16 90 00 } //1
		$a_02_1 = {80 f9 30 7c 90 01 01 80 f9 39 7f 90 01 01 6b c0 0a 0f be c9 8d 44 08 d0 42 8a 0a 80 f9 20 90 00 } //1
		$a_02_2 = {50 8b c7 e8 90 01 04 81 7d 90 01 01 6a 6f 62 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}