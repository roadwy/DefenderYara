
rule TrojanProxy_Win32_Hioles_B{
	meta:
		description = "TrojanProxy:Win32/Hioles.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 10 8b 09 81 f9 47 45 54 20 74 90 01 01 81 f9 50 4f 53 54 74 90 01 01 56 50 ff 75 10 ff 75 08 ff 15 90 00 } //01 00 
		$a_01_1 = {50 ff 74 24 14 c7 00 85 b2 04 77 c7 40 04 ce 38 e0 33 c6 40 08 04 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}