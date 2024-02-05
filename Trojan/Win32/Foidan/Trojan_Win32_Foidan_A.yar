
rule Trojan_Win32_Foidan_A{
	meta:
		description = "Trojan:Win32/Foidan.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 4f 00 49 00 44 00 43 00 54 00 52 00 4c 00 25 00 64 00 00 00 } //01 00 
		$a_01_1 = {46 00 4f 00 43 00 54 00 52 00 4c 00 4d 00 00 00 } //03 00 
		$a_03_2 = {8a 00 3c eb 74 19 3c e9 74 15 3c e8 74 11 3c 68 74 0d 68 88 13 00 00 ff 15 90 01 04 eb dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}