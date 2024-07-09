
rule TrojanDownloader_Win32_Bubnix_A{
	meta:
		description = "TrojanDownloader:Win32/Bubnix.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 30 8b 4d 0c 56 8b 75 08 57 8a 16 ff 4d 10 32 d0 } //1
		$a_03_1 = {6a 02 6a 0b 57 ff 75 08 ff 15 ?? ?? ?? ?? 8b d8 3b df 74 4c } //1
		$a_01_2 = {2f 61 70 70 6c 69 63 61 74 69 6f 6e 64 61 74 61 2e 62 69 6e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}