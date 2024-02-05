
rule Trojan_Win64_Sirefef_AO{
	meta:
		description = "Trojan:Win64/Sirefef.AO,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 73 06 44 0f b7 5b 14 41 3b f6 74 23 49 8d 7c 1b 2c 8b 17 8b 4f 90 01 01 44 8b 47 90 01 01 48 03 55 10 49 03 cd e8 90 01 04 48 83 c7 28 41 03 f7 75 e2 48 8b bd b0 00 00 00 4c 8d 4d 00 41 b8 05 00 00 00 48 2b 7b 30 b2 01 49 8b cd ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}