
rule Trojan_Win32_Torrost_A{
	meta:
		description = "Trojan:Win32/Torrost.A,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {68 4c cc 00 00 ff d0 0f b7 c8 51 68 7f 00 00 01 e8 90 01 02 ff ff 8b f0 85 f6 0f 84 90 01 01 01 00 00 8b 15 90 01 04 8b 90 02 05 6a 00 6a 03 90 00 } //01 00 
		$a_01_1 = {2e 6f 6e 69 6f 6e 2f 63 74 34 2e 70 68 70 } //01 00 
		$a_01_2 = {53 6f 63 6b 73 50 6f 72 74 20 35 32 33 30 30 20 2d 2d 46 61 73 63 69 73 74 46 69 72 65 77 61 6c 6c 20 31 } //00 00 
		$a_00_3 = {5d 04 00 00 2c 09 03 80 5c 21 } //00 00 
	condition:
		any of ($a_*)
 
}