
rule TrojanDownloader_Win32_Agent_QY{
	meta:
		description = "TrojanDownloader:Win32/Agent.QY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 e8 81 f9 9d 71 82 4e 74 1c 81 f9 9c 71 82 4e 74 14 81 f9 9b c7 81 fa 74 0c } //1
		$a_01_1 = {8b 45 00 8a 14 38 03 c7 88 51 ff 8a 40 01 88 01 83 c7 04 83 c1 02 3b 7d 04 76 e5 } //1
		$a_03_2 = {c7 40 04 00 ?? 02 00 c7 00 01 00 00 00 89 48 08 ff d7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}