
rule Trojan_Win32_Injector_YG_bit{
	meta:
		description = "Trojan:Win32/Injector.YG!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 40 18 83 ec 10 56 57 be 90 01 04 a3 90 01 04 e8 90 01 04 50 0f b6 05 00 10 40 00 50 e8 90 01 04 a3 90 01 04 85 c0 74 17 be 90 01 04 e8 90 01 04 50 6a 01 e8 90 00 } //01 00 
		$a_01_1 = {8a 0a 84 c9 74 15 32 0e 2a 4d fc fe c9 ff 45 fc 88 0c 10 42 39 7d fc 72 e7 eb 03 } //00 00 
	condition:
		any of ($a_*)
 
}