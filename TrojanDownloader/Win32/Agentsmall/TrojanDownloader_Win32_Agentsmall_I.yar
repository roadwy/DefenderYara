
rule TrojanDownloader_Win32_Agentsmall_I{
	meta:
		description = "TrojanDownloader:Win32/Agentsmall.I,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 f2 87 1b 01 14 66 8b 30 66 46 66 89 30 43 81 e2 72 73 35 0b 66 8b 10 66 42 66 89 10 46 40 81 f7 c4 f5 4a 2b 40 81 e6 aa e8 25 1a bb 76 53 40 00 3b d8 75 cb } //00 00 
	condition:
		any of ($a_*)
 
}