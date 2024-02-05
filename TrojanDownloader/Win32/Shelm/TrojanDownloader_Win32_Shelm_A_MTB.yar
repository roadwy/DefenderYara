
rule TrojanDownloader_Win32_Shelm_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Shelm.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {30 40 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 10 00 00 00 c7 44 24 04 24 30 40 00 89 04 24 a1 } //02 00 
		$a_03_1 = {83 ec 18 a3 90 01 01 30 40 00 66 c7 05 90 01 01 30 40 00 02 00 0f b7 45 f2 0f b7 c0 89 04 24 a1 90 01 02 40 00 ff d0 83 ec 04 66 a3 90 01 01 30 40 00 8b 45 f4 89 04 24 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}