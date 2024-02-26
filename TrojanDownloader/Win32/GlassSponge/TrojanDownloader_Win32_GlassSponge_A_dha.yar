
rule TrojanDownloader_Win32_GlassSponge_A_dha{
	meta:
		description = "TrojanDownloader:Win32/GlassSponge.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 28 2a 41 70 70 43 61 63 68 65 52 6f 61 6d 29 2e 65 78 65 63 75 74 65 } //01 00  main.(*AppCacheRoam).execute
		$a_01_1 = {6d 61 69 6e 2e 28 2a 50 6f 77 65 72 53 68 65 6c 6c 29 2e 75 7a 6d 52 65 73 74 6f 72 69 6e 67 } //00 00  main.(*PowerShell).uzmRestoring
	condition:
		any of ($a_*)
 
}