
rule TrojanDownloader_Win32_Agent_KL{
	meta:
		description = "TrojanDownloader:Win32/Agent.KL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 b9 a8 61 00 00 f7 f9 81 c2 ac 0d 00 00 89 15 90 01 04 89 54 90 01 02 ff 15 90 01 04 8b d0 b8 d3 4d 62 10 f7 e2 c1 ea 06 90 00 } //01 00 
		$a_01_1 = {99 b9 03 00 00 00 f7 f9 83 c2 07 69 d2 09 03 00 00 52 } //00 00 
	condition:
		any of ($a_*)
 
}