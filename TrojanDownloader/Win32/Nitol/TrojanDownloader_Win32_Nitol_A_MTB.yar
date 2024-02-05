
rule TrojanDownloader_Win32_Nitol_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Nitol.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 64 24 0c 68 90 09 19 00 ff 15 04 90 01 01 40 00 8b f0 68 90 01 02 40 00 56 ff 15 10 90 01 01 40 00 51 8b f8 8b cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}