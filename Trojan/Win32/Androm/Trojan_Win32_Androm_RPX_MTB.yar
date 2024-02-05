
rule Trojan_Win32_Androm_RPX_MTB{
	meta:
		description = "Trojan:Win32/Androm.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {56 51 57 e8 90 01 04 83 c4 0c 6a 40 68 00 30 00 00 56 6a 00 ff 15 90 01 04 8b 4c 24 60 2b 4c 24 5c 51 57 50 89 44 24 60 e8 90 00 } //01 00 
		$a_01_1 = {33 00 38 00 2e 00 35 00 35 00 2e 00 31 00 39 00 34 00 2e 00 31 00 30 00 34 00 } //01 00 
		$a_01_2 = {6f 00 75 00 74 00 70 00 75 00 74 00 5f 00 33 00 32 00 2e 00 62 00 69 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}