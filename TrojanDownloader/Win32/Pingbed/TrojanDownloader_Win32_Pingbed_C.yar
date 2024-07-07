
rule TrojanDownloader_Win32_Pingbed_C{
	meta:
		description = "TrojanDownloader:Win32/Pingbed.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 ff 0f 1f 00 ff 15 90 01 04 89 45 90 01 01 83 7d 90 1b 01 00 74 20 6a 00 8b 4d f8 51 ff 15 90 01 04 89 45 90 01 01 83 7d 90 1b 04 00 75 0b 68 f4 01 00 00 ff 15 90 00 } //1
		$a_01_1 = {21 40 23 74 69 75 71 23 40 21 } //1 !@#tiuq#@!
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}