
rule Trojan_Win32_Dapterup_A_C{
	meta:
		description = "Trojan:Win32/Dapterup.A!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 64 65 6c 2e 62 61 74 00 } //01 00 
		$a_01_1 = {31 08 3b 15 24 12 2b 05 37 03 37 } //01 00 
		$a_00_2 = {5e 03 1e 67 9b 0c bb 56 66 6b 6d 64 4e c8 80 06 f1 fc } //02 00 
		$a_01_3 = {8a 54 08 ff 30 14 08 48 75 } //00 00 
		$a_00_4 = {5d 04 00 00 } //ff 0f 
	condition:
		any of ($a_*)
 
}