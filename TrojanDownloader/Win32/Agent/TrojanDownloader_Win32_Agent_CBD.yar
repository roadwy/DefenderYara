
rule TrojanDownloader_Win32_Agent_CBD{
	meta:
		description = "TrojanDownloader:Win32/Agent.CBD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 4e 53 49 53 64 6c 2e 64 6c 6c 00 fd 82 80 00 68 74 74 70 3a 2f 2f 70 73 76 73 74 61 74 73 2e 69 6e 66 6f 2f 68 72 74 62 62 6e 2f 72 77 76 73 6b 69 2e 65 78 65 00 64 6f 77 6e 6c 6f 61 64 00 fd 8a 80 00 73 75 63 63 65 73 73 00 fd 82 80 20 2f 71 00 52 75 6e 74 69 6d 65 20 56 42 35 20 4f 4b 2e 00 30 00 fd 9a 80 5c 44 69 61 6c 65 72 2e 64 6c 6c 00 41 74 74 65 6d 70 74 43 6f 6e 6e 65 63 74 00 6f 6e 6c 69 6e 65 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}