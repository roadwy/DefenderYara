
rule TrojanDownloader_Win64_Shelm_A_MTB{
	meta:
		description = "TrojanDownloader:Win64/Shelm.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 20 2b 45 fc 89 c1 48 8b 55 f0 48 8b 45 10 41 b9 00 00 00 00 41 89 c8 48 89 c1 48 8b 05 90 01 02 00 00 ff d0 89 45 ec 8b 45 ec 48 98 48 01 45 f0 8b 45 ec 01 45 fc 83 7d ec ff 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}