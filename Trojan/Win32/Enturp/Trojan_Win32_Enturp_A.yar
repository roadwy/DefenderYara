
rule Trojan_Win32_Enturp_A{
	meta:
		description = "Trojan:Win32/Enturp.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a c1 c0 e8 04 c0 e1 04 0a c1 88 02 8a 4c 16 01 42 84 c9 75 eb } //02 00 
		$a_03_1 = {8b f0 56 6a 01 6a 74 68 90 01 04 e8 90 01 04 83 c4 1c 8b 5c 24 20 90 00 } //01 00 
		$a_01_2 = {5b 45 4e 54 5d 0d 0a 00 } //00 00 
	condition:
		any of ($a_*)
 
}