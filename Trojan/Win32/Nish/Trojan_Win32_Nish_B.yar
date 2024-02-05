
rule Trojan_Win32_Nish_B{
	meta:
		description = "Trojan:Win32/Nish.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 49 45 41 64 76 42 48 4f 46 61 63 74 6f 72 79 } //01 00 
		$a_03_1 = {54 49 45 4d 6f 6e 69 74 6f 72 90 02 10 68 74 74 70 3a 2f 2f 90 00 } //02 00 
		$a_02_2 = {8b 4a f8 41 7e 90 01 01 f0 ff 42 f8 87 10 85 d2 74 90 01 01 8b 4a f8 49 7c 90 01 01 f0 ff 4a f8 75 90 01 01 8d 42 f8 e8 90 00 } //02 00 
		$a_03_3 = {8b 45 08 66 c7 00 ff ff 8b c3 8b 15 90 01 04 e8 90 01 04 8b 45 0c 50 8b 45 10 50 8b 45 14 50 57 53 8d 45 f8 8b d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}