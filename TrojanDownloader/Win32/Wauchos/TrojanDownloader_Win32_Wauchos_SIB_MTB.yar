
rule TrojanDownloader_Win32_Wauchos_SIB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Wauchos.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {31 d2 8b 75 08 ac 84 c0 74 90 01 01 0c 90 01 01 30 c2 c1 c2 90 01 01 eb 90 01 01 89 d0 90 00 } //1
		$a_02_1 = {8b 5d 08 8b 43 3c 8d 44 18 18 8d 40 60 8b 00 85 c0 74 90 01 01 01 d8 89 45 90 01 01 8b 70 20 01 de 8b 48 18 85 c9 90 18 ad 01 d8 50 e8 90 01 04 3b 45 0c 90 18 83 ee 90 01 01 8b 45 90 1b 01 2b 70 20 29 de d1 ee 01 de 03 70 24 0f b7 36 c1 e6 02 01 de 03 70 1c 8b 36 01 de 89 f0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}