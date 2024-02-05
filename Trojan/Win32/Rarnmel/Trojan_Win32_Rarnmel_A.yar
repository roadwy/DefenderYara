
rule Trojan_Win32_Rarnmel_A{
	meta:
		description = "Trojan:Win32/Rarnmel.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 68 d4 fe ff ff 56 ff 15 90 01 02 00 10 b9 4a 00 00 00 90 00 } //01 00 
		$a_03_1 = {68 2c 01 00 00 50 56 c7 44 24 1c 00 00 00 00 ff 15 90 01 02 00 10 56 ff 15 90 01 02 00 10 8d 4c 24 10 90 00 } //01 00 
		$a_01_2 = {83 f8 01 74 0d 68 c8 00 00 00 ff d7 46 83 fe 14 7c e4 } //00 00 
	condition:
		any of ($a_*)
 
}