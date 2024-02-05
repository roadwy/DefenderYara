
rule Trojan_Win32_Vundo_gen_BN{
	meta:
		description = "Trojan:Win32/Vundo.gen!BN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 56 55 4b 2e 64 6c 6c 00 64 00 } //02 00 
		$a_03_1 = {c6 45 fc c2 c6 45 fd 10 88 5d fe ff 15 90 01 04 8b f8 3b fb 0f 84 90 00 } //01 00 
		$a_01_2 = {03 40 3c 8b 70 54 2b 70 2c } //01 00 
		$a_01_3 = {8b 48 3c 03 c8 89 4e 14 8b 51 2c 03 d0 8b 41 1c } //00 00 
	condition:
		any of ($a_*)
 
}