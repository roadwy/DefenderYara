
rule TrojanDownloader_Win32_PterodoGen_A_dha{
	meta:
		description = "TrojanDownloader:Win32/PterodoGen.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_43_0 = {83 7d d0 01 0f 85 90 01 04 81 7d 90 01 01 aa 00 00 00 0f 85 90 00 01 } //00 1a 
		$a_83_1 = {01 74 90 01 01 33 c0 eb 90 01 01 8b 55 08 81 7a 08 aa 00 00 00 74 90 00 01 00 18 43 66 83 7c 24 14 01 0f 85 90 01 04 81 7c 90 01 02 aa 00 00 00 0f 85 90 00 00 00 5d 04 00 00 43 00 05 80 5c 28 00 00 44 } //00 05 
	condition:
		any of ($a_*)
 
}