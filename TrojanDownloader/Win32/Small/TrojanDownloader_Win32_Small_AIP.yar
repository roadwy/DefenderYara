
rule TrojanDownloader_Win32_Small_AIP{
	meta:
		description = "TrojanDownloader:Win32/Small.AIP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {40 3b c1 72 f3 38 5d 0b 75 16 80 bd 90 01 04 4d 75 38 80 bd 90 01 04 5a 75 2f c6 45 0b 01 90 00 } //1
		$a_02_1 = {68 74 74 70 3a 2f 2f 6d 66 65 65 64 2e 69 66 2e 75 61 2f 73 6c 2f 67 65 74 2e 70 68 70 90 02 03 74 6d 70 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}