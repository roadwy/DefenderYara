
rule TrojanDownloader_Win32_Agent_AFN{
	meta:
		description = "TrojanDownloader:Win32/Agent.AFN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {8a 0e 8a 10 2a d1 88 10 8a ca 8a 16 32 d1 46 88 10 40 } //1
		$a_03_1 = {46 c6 44 24 ?? 69 c6 44 24 ?? 65 c6 44 24 ?? 41 c6 44 24 ?? 00 c6 44 24 ?? 75 c6 44 24 ?? 72 } //1
		$a_03_2 = {6d c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 5c c6 44 24 ?? 75 } //1
		$a_00_3 = {5c 54 61 73 6b 73 5c 63 6f 6e 69 6d 65 2e 65 78 65 } //1 \Tasks\conime.exe
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}