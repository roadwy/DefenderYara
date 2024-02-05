
rule TrojanDownloader_Win32_Obcatde_A{
	meta:
		description = "TrojanDownloader:Win32/Obcatde.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 8b d8 8b 43 60 8a 40 6c 88 43 70 84 c0 74 4b 8b 43 60 80 78 78 00 74 25 66 83 bb 82 00 00 00 00 74 47 8b 50 70 52 8b 50 68 52 8b 48 4c 8b d3 8b 83 84 00 00 00 ff 93 80 00 00 00 eb 2c } //01 00 
		$a_01_1 = {80 7f 78 00 74 17 8b 87 8c 00 00 00 99 3b 57 74 75 03 3b 47 70 0f 94 c0 88 47 6c eb 1b } //00 00 
	condition:
		any of ($a_*)
 
}