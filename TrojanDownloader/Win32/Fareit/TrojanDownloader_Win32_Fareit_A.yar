
rule TrojanDownloader_Win32_Fareit_A{
	meta:
		description = "TrojanDownloader:Win32/Fareit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 48 64 43 37 31 66 75 71 53 56 65 37 33 46 68 } //1 fHdC71fuqSVe73Fh
		$a_01_1 = {0f be 08 33 f1 89 75 c4 8a 55 c4 88 55 dc 8a 45 dc 50 8d 4d b4 } //1
		$a_01_2 = {6a 00 6a 01 8b 45 e0 50 ff 55 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}