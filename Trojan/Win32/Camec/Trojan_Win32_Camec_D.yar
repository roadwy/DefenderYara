
rule Trojan_Win32_Camec_D{
	meta:
		description = "Trojan:Win32/Camec.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 00 37 00 36 00 38 00 37 00 26 00 a8 00 53 00 37 00 36 00 73 00 a8 00 25 00 24 00 34 00 35 00 33 00 32 00 33 00 34 00 35 00 36 00 37 00 21 00 40 00 23 00 24 00 25 00 } //01 00 
		$a_01_1 = {35 00 41 00 34 00 34 00 35 00 31 00 30 00 38 00 } //00 00  5A445108
	condition:
		any of ($a_*)
 
}