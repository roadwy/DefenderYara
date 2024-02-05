
rule Trojan_Win32_Injector_AAA_bit{
	meta:
		description = "Trojan:Win32/Injector.AAA!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 48 fc 88 4d f3 0f b6 55 f3 81 f2 90 01 01 00 00 00 52 8b 45 f8 50 68 34 c1 40 00 8b 4d f8 51 e8 90 01 03 ff 90 00 } //01 00 
		$a_03_1 = {6a 02 6a 01 8b 95 90 01 01 ff ff ff 52 ff 55 fc 89 85 90 00 } //01 00 
		$a_03_2 = {6a 00 6a 00 6a 24 6a 00 6a 00 6a 00 ff 95 90 01 02 ff ff 50 6a 00 ff 95 90 01 01 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}