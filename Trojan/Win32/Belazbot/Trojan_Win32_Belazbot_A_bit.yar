
rule Trojan_Win32_Belazbot_A_bit{
	meta:
		description = "Trojan:Win32/Belazbot.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 8b 45 f0 01 c2 8b 4d f4 8b 45 08 01 c8 8a 00 83 f0 02 88 02 ff 45 f4 } //02 00 
		$a_03_1 = {89 45 d4 c7 04 24 90 01 02 40 00 e8 90 01 02 00 00 89 45 d0 c7 04 24 90 01 02 40 00 e8 90 01 02 00 00 89 45 cc c7 04 24 90 01 02 40 00 e8 90 01 02 00 00 89 45 c8 c7 04 24 90 01 02 40 00 e8 90 01 02 00 00 89 45 c4 c7 04 24 90 01 02 40 00 e8 90 01 02 00 00 90 00 } //01 00 
		$a_01_2 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a 0d 0a 00 72 62 00 77 62 2b 00 0d 0a 0d 0a 00 4d 5a 00 } //00 00 
	condition:
		any of ($a_*)
 
}