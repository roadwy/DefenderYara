
rule TrojanDownloader_Win32_Agent_ZDG{
	meta:
		description = "TrojanDownloader:Win32/Agent.ZDG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 61 72 70 70 30 39 33 34 2e 69 65 73 70 61 6e 61 2e 65 73 5c 90 02 08 2e 6a 70 67 90 00 } //1
		$a_03_1 = {6a 00 6a 01 68 90 01 04 e8 90 01 04 83 f8 01 1b c0 40 3c 01 75 90 01 01 6a 00 6a 00 68 90 01 04 68 90 01 04 6a 00 e8 90 01 04 ba 90 01 04 a1 90 01 04 8b 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}