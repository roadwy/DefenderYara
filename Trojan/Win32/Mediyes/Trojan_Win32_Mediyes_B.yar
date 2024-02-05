
rule Trojan_Win32_Mediyes_B{
	meta:
		description = "Trojan:Win32/Mediyes.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 08 8b 45 f0 30 08 43 3b 5e 14 72 90 14 8b fb 8b c6 e8 90 01 04 89 45 f0 8d 7b ff 8b c6 e8 90 00 } //01 00 
		$a_03_1 = {8d 47 04 66 8b 44 58 fe 66 31 06 8b 47 14 43 3b d8 72 90 14 83 7f 18 08 72 05 8b 77 04 eb 03 8d 77 04 8d 43 ff 3b 47 14 8d 34 5e 76 05 e8 90 01 04 83 7f 18 08 72 05 8b 47 04 eb 03 90 00 } //01 00 
		$a_01_2 = {67 02 11 17 0c 01 08 0f 0e 49 5e 18 18 00 } //01 00 
		$a_00_3 = {5c 00 00 00 72 00 72 00 00 00 00 00 53 00 79 00 73 00 45 00 76 00 74 00 43 } //00 00 
	condition:
		any of ($a_*)
 
}