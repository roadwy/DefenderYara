
rule Trojan_Win32_Sefnit_E{
	meta:
		description = "Trojan:Win32/Sefnit.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 b7 a3 42 17 90 04 01 03 6a e9 eb 90 00 } //01 00 
		$a_03_1 = {01 40 00 80 90 09 03 00 c7 45 90 00 } //01 00 
		$a_03_2 = {55 83 2c 24 90 01 01 90 18 6a 90 01 01 90 18 68 90 01 04 90 18 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}