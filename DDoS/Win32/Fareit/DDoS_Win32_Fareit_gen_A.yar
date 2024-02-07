
rule DDoS_Win32_Fareit_gen_A{
	meta:
		description = "DDoS:Win32/Fareit.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 0e b8 3d 00 00 00 c7 45 fc 01 00 00 00 eb 1b b8 26 00 00 00 } //02 00 
		$a_01_1 = {8b 40 0c 0b c0 75 07 b8 ff ff ff ff eb 04 8b 00 8b 00 } //02 00 
		$a_01_2 = {ff 85 0c f9 ff ff 83 bd 0c f9 ff ff 0a 73 05 e9 4a ff ff ff } //01 00 
		$a_01_3 = {50 4e 59 44 4f 53 30 30 } //01 00  PNYDOS00
		$a_01_4 = {43 52 59 50 54 45 44 30 } //01 00  CRYPTED0
		$a_01_5 = {42 49 4e 53 54 52 30 30 } //00 00  BINSTR00
	condition:
		any of ($a_*)
 
}