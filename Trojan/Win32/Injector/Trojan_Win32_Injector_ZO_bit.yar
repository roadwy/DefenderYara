
rule Trojan_Win32_Injector_ZO_bit{
	meta:
		description = "Trojan:Win32/Injector.ZO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 f4 03 95 90 01 03 ff 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 e9 90 01 03 ff 90 00 } //01 00 
		$a_03_1 = {8b 55 f8 8b 02 33 85 90 01 03 ff 8b 4d f8 89 01 5f 5e 5b 8b e5 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}