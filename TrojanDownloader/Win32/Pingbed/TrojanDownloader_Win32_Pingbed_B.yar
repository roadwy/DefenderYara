
rule TrojanDownloader_Win32_Pingbed_B{
	meta:
		description = "TrojanDownloader:Win32/Pingbed.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 30 10 40 4e 75 f7 } //1
		$a_01_1 = {80 7d 08 1b 75 12 80 7d 09 34 75 0c 80 7d 0a 5e 75 06 80 7d 0b 2d 74 08 f6 46 0c 10 75 73 eb cf } //1
		$a_01_2 = {80 bd 85 f9 ff ff 75 75 16 80 bd 86 f9 ff ff 69 75 0d 80 bd 87 f9 ff ff 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}