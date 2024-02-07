
rule Trojan_Win32_Clopdor_A{
	meta:
		description = "Trojan:Win32/Clopdor.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {99 b9 a8 03 00 00 f7 f9 8b 55 08 } //01 00 
		$a_01_1 = {05 d0 07 00 00 50 ff 15 } //02 00 
		$a_03_2 = {6a 00 6a 00 6a 00 8b 55 ec 52 ff 15 90 01 02 00 10 6a 05 90 00 } //02 00 
		$a_03_3 = {8a 0a 32 8c 05 90 01 02 ff ff 8b 95 90 01 02 ff ff 03 95 90 01 02 ff ff 88 0a eb bd 6a 00 90 00 } //01 00 
		$a_01_4 = {21 63 68 63 6b 4f 4b 21 } //00 00  !chckOK!
	condition:
		any of ($a_*)
 
}