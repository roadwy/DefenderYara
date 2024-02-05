
rule Trojan_Win32_Inject_ZG_bit{
	meta:
		description = "Trojan:Win32/Inject.ZG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 01 8a 92 90 01 04 32 da 88 1c 01 90 00 } //01 00 
		$a_03_1 = {8a 18 8a 4c 90 01 02 02 d9 88 18 90 00 } //01 00 
		$a_03_2 = {8a 18 8b 74 90 01 02 8a 8a 90 01 04 32 d9 46 85 d2 88 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}