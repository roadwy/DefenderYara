
rule Trojan_Win32_Bamital_D{
	meta:
		description = "Trojan:Win32/Bamital.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 38 63 75 72 73 74 06 } //01 00 
		$a_03_1 = {74 16 5e 59 c0 06 90 01 01 83 c6 01 e2 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}