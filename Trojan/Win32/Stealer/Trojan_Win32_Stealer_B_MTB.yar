
rule Trojan_Win32_Stealer_B_MTB{
	meta:
		description = "Trojan:Win32/Stealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 44 0c 20 04 0e 88 84 0c c0 00 00 00 41 3b ca 7c ee } //01 00 
		$a_01_1 = {8a 44 0c 20 34 e3 88 84 0c cc 00 00 00 41 3b ca 7c ee } //01 00 
		$a_01_2 = {8a 44 0c 2c 34 15 88 84 0c 00 01 00 00 41 83 f9 0c 7c ed } //00 00 
	condition:
		any of ($a_*)
 
}