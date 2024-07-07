
rule TrojanDownloader_Win32_Zlob_ANW{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {01 00 00 43 90 09 0b 00 88 9c 24 90 01 01 01 00 00 c6 84 24 90 00 } //2
		$a_03_1 = {01 00 00 65 c6 84 24 90 01 01 01 00 00 72 e8 90 09 04 00 c6 84 24 90 00 } //2
		$a_01_2 = {8a 04 0e 32 44 24 14 88 01 49 ff 4c 24 0c 75 f0 } //1
		$a_01_3 = {00 6d 6d 6d 00 77 74 66 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}