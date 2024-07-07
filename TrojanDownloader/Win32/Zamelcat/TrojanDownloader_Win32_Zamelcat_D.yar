
rule TrojanDownloader_Win32_Zamelcat_D{
	meta:
		description = "TrojanDownloader:Win32/Zamelcat.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff ff 56 50 ff 15 90 01 04 83 c4 18 33 f6 90 09 1e 00 ff 15 90 01 04 6a 03 e8 90 01 04 50 8d 85 90 01 02 ff ff 50 68 90 01 04 8d 85 90 00 } //1
		$a_03_1 = {3a 36 2f 2e 78 2f 90 0f 05 00 2e 65 78 65 00 90 05 10 01 00 25 73 5c 25 73 2e 65 78 65 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}