
rule Trojan_Win32_Scar_J{
	meta:
		description = "Trojan:Win32/Scar.J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 6a 00 6a 00 6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 } //01 00 
		$a_03_1 = {0f b6 08 83 f9 11 90 03 02 01 0f 8e 7e 90 02 04 8b 85 90 01 04 0f b6 08 83 e9 11 89 4d 90 02 04 8b 95 90 1b 02 83 c2 01 90 00 } //01 00 
		$a_00_2 = {5c 70 61 79 6c 6f 61 64 5f 6c 6f 61 64 65 72 5f 6f 62 66 75 73 63 61 74 65 64 5c } //01 00  \payload_loader_obfuscated\
		$a_03_3 = {83 7d 14 01 75 90 01 01 68 90 01 04 68 e8 03 00 00 6a 00 6a 00 e8 90 00 } //01 00 
		$a_00_4 = {8b 8d ac 00 00 00 8b 10 2b 11 8b 85 cc 00 00 00 89 10 8b 85 d8 00 00 00 8b 08 33 4d 2c } //00 00 
	condition:
		any of ($a_*)
 
}