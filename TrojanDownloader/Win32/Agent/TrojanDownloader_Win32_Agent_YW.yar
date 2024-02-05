
rule TrojanDownloader_Win32_Agent_YW{
	meta:
		description = "TrojanDownloader:Win32/Agent.YW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 3d 7e 00 75 02 33 c0 8a 19 8b d0 81 e2 ff ff 00 00 8a 54 54 0c 32 da 40 88 19 41 4e 75 e1 } //01 00 
		$a_03_1 = {50 c6 00 57 c6 86 90 01 04 49 c6 86 90 01 04 4e c6 86 90 01 04 49 c6 86 90 01 04 4e c6 86 90 01 04 45 c6 86 90 01 04 54 c6 86 90 01 04 2e c6 86 90 01 04 64 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}