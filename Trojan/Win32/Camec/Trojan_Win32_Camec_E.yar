
rule Trojan_Win32_Camec_E{
	meta:
		description = "Trojan:Win32/Camec.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 00 44 00 34 00 32 00 34 00 31 00 34 00 35 00 30 00 46 00 31 00 42 00 31 00 41 00 } //01 00 
		$a_01_1 = {35 00 36 00 30 00 43 00 36 00 39 00 34 00 32 00 35 00 43 00 35 00 41 00 35 00 31 00 35 00 39 00 34 00 32 00 34 00 36 00 36 00 46 00 } //01 00 
	condition:
		any of ($a_*)
 
}