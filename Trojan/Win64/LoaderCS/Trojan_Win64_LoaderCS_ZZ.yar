
rule Trojan_Win64_LoaderCS_ZZ{
	meta:
		description = "Trojan:Win64/LoaderCS.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 53 48 83 ec 20 8b 1d 90 01 04 8b 0d 90 01 04 ba 73 10 00 00 ff 15 90 01 04 4c 8b d8 8b 05 90 01 04 41 03 c3 8b c8 48 8b 05 90 01 04 0f b6 0c 08 48 8b 05 90 01 04 0f b6 14 18 03 d1 8b 0d 90 01 04 48 8b 05 90 01 04 88 14 08 48 83 c4 20 5b c3 90 00 } //01 00 
		$a_01_1 = {48 83 c4 40 ff e1 } //01 00 
		$a_03_2 = {2d 35 19 00 00 89 44 90 01 02 41 b9 00 30 00 00 44 8b 90 01 03 33 d2 48 8b 90 01 03 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}