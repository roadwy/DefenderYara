
rule Trojan_Win32_Lyinos_A{
	meta:
		description = "Trojan:Win32/Lyinos.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 54 6a 00 6a 01 6a 14 e4 90 01 01 59 85 c0 75 90 00 } //01 00 
		$a_01_1 = {ff 30 8f 86 b0 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}