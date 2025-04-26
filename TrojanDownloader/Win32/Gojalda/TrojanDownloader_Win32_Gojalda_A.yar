
rule TrojanDownloader_Win32_Gojalda_A{
	meta:
		description = "TrojanDownloader:Win32/Gojalda.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 45 ec 4d c6 45 ed 41 c6 45 ee 6f c6 45 ef 67 c6 45 f0 61 c6 45 f1 65 } //1
		$a_01_1 = {8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c6 } //1
		$a_01_2 = {c6 45 d4 53 c6 45 d5 68 c6 45 d6 65 c6 45 d7 6c c6 45 d8 6c c6 45 d9 45 c6 45 da 78 } //1
		$a_01_3 = {c6 45 f8 50 c6 45 f9 4f c6 45 fa 53 c6 45 fb 54 c6 45 fc 00 68 } //1
		$a_01_4 = {2b 44 24 04 c6 01 e9 83 e8 05 8b d0 c1 ea 08 88 51 02 8b d0 88 41 01 c1 ea 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}