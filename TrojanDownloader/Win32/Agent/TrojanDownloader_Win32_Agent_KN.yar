
rule TrojanDownloader_Win32_Agent_KN{
	meta:
		description = "TrojanDownloader:Win32/Agent.KN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 24 52 50 c7 45 ?? 3a 2f 2f 77 c7 45 ?? 65 62 72 65 c7 45 ?? 67 2e 33 33 c7 45 ?? 32 32 2e 6f c7 45 ?? 72 67 2f 69 c7 45 ?? 6e 64 65 78 c7 45 ?? 2e 61 73 70 89 75 ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}