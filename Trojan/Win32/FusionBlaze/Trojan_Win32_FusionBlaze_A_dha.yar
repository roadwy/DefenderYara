
rule Trojan_Win32_FusionBlaze_A_dha{
	meta:
		description = "Trojan:Win32/FusionBlaze.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 1c 56 6a 06 6a 01 6a 02 ff 15 90 01 04 6a 00 6a 00 8b f0 8d 45 fc 50 6a 90 00 } //01 00 
		$a_01_1 = {0c 8d 4d e4 51 6a 0c 8d 55 f0 52 68 04 00 00 98 56 c7 45 f0 01 00 00 00 c7 45 f4 00 f4 01 00 c7 } //01 00 
		$a_03_2 = {45 f8 e8 03 00 00 c7 45 fc 00 00 00 00 ff 15 90 01 04 40 f7 d8 1b c0 23 c6 5e 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}