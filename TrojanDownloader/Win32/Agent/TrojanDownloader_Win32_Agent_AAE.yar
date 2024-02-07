
rule TrojanDownloader_Win32_Agent_AAE{
	meta:
		description = "TrojanDownloader:Win32/Agent.AAE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 18 32 da 88 18 40 49 75 f6 } //01 00 
		$a_03_1 = {c6 44 24 29 2f c6 44 24 2a 63 88 90 01 01 24 2b c6 44 24 2c 64 c6 44 24 2d 65 90 00 } //01 00 
		$a_00_2 = {25 73 26 4f 53 3d 77 49 4e 78 70 26 49 50 3d 25 73 } //00 00  %s&OS=wINxp&IP=%s
	condition:
		any of ($a_*)
 
}