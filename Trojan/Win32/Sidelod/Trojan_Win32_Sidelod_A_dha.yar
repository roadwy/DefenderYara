
rule Trojan_Win32_Sidelod_A_dha{
	meta:
		description = "Trojan:Win32/Sidelod.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff d6 8b 45 f4 8a 0c 90 01 01 ff 05 90 01 04 90 02 08 2a cb 90 02 08 80 f1 3f 6a 00 02 cb 90 02 05 88 0f ff d6 47 ff 4d fc 75 90 00 } //02 00 
		$a_03_1 = {6a 40 6a 10 57 ff 90 01 01 85 c0 90 02 14 ff d6 90 02 0a bb 90 01 04 2b df 6a 00 83 eb 05 6a 00 89 5d fc 90 00 } //01 00 
		$a_01_2 = {6a 00 6a 00 c6 07 e9 ff d6 } //01 00 
		$a_03_3 = {51 68 19 00 02 00 6a 00 6a 10 68 90 01 04 b3 90 01 01 e8 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}