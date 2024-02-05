
rule Virus_Win32_Viking_JB{
	meta:
		description = "Virus:Win32/Viking.JB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 90 01 04 8b 55 f4 8b c7 e8 90 01 04 ff 45 f8 4e 75 d9 90 00 } //01 00 
		$a_03_1 = {0f 84 2d 01 00 00 6a 00 53 e8 90 01 02 ff ff 8b f0 81 fe 00 00 00 01 0f 83 11 01 00 00 3b 35 90 01 04 7c 34 90 00 } //01 00 
		$a_03_2 = {8b 55 fc e8 90 01 02 ff ff 8b 85 90 01 02 ff ff e8 90 01 02 ff ff 56 57 e8 90 01 02 ff ff 85 c0 75 84 57 e8 90 01 02 ff ff c7 06 16 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}