
rule TrojanDownloader_Win32_Agent_AAQ{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 65 00 74 00 75 00 70 00 00 00 00 00 25 00 73 00 5c 00 61 00 70 00 70 00 25 00 64 00 2e 00 74 00 6d 00 70 00 } //1
		$a_01_1 = {eb 19 8a d1 c0 ea 02 08 10 40 c0 e1 06 88 08 ba 03 00 00 00 eb 05 08 08 } //1
		$a_01_2 = {c7 84 24 40 03 00 00 00 00 00 00 8b 54 24 20 52 50 e8 69 00 00 00 c7 84 24 40 03 00 00 ff ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}