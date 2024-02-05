
rule Trojan_Win32_Hilasy_A{
	meta:
		description = "Trojan:Win32/Hilasy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6f 69 61 51 30 72 68 64 } //01 00 
		$a_03_1 = {68 70 17 00 00 6a 00 6a 00 ff 15 90 01 04 e8 90 01 04 33 c0 c3 90 09 07 00 c7 04 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}