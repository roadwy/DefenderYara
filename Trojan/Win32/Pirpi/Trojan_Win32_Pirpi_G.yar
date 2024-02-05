
rule Trojan_Win32_Pirpi_G{
	meta:
		description = "Trojan:Win32/Pirpi.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 85 84 fe ff ff 50 ff 15 90 01 04 8d 4d 90 90 51 8d 55 fc 52 68 71 17 00 00 e8 90 00 } //01 00 
		$a_03_1 = {81 7d 8c 93 00 00 00 72 07 33 c0 e9 90 01 01 01 00 00 b9 1a 00 00 00 33 c0 8d 7d 94 f3 ab 66 ab aa b9 1a 00 00 00 90 00 } //01 00 
		$a_01_2 = {ff d5 99 b9 1a 00 00 00 f7 f9 46 3b f7 8a 54 14 10 88 54 1e ff } //01 00 
		$a_03_3 = {81 bd 00 f5 ff ff 00 10 00 00 73 14 8b 95 f0 f6 ff ff 52 ff 15 90 01 04 33 c0 e9 90 01 02 00 00 6a 00 6a 00 68 00 08 00 00 8b 85 f0 f6 ff ff 50 ff 15 90 01 04 b9 00 02 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}