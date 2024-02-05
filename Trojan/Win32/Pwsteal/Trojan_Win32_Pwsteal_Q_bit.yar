
rule Trojan_Win32_Pwsteal_Q_bit{
	meta:
		description = "Trojan:Win32/Pwsteal.Q!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f1 d1 ea 66 8b 44 55 90 01 01 66 89 04 5e 43 3b df 90 09 0a 00 e8 90 01 04 33 d2 6a 90 01 01 59 90 00 } //01 00 
		$a_03_1 = {05 c3 9e 26 00 a3 90 01 04 c1 e8 10 25 ff 7f 00 00 c3 90 09 0a 00 69 05 90 01 04 fd 43 03 00 90 00 } //01 00 
		$a_03_2 = {6a 6c 66 89 85 90 01 01 fe ff ff 58 6a 77 66 89 85 90 01 01 fe ff ff 58 6a 61 66 89 85 90 01 01 fe ff ff 58 6a 70 66 89 85 90 01 01 fe ff ff 58 6a 69 66 89 85 90 01 01 fe ff ff 58 66 89 85 90 01 01 fe ff ff 33 c0 66 89 85 90 01 01 fe ff ff ab 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}