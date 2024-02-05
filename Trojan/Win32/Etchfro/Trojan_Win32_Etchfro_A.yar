
rule Trojan_Win32_Etchfro_A{
	meta:
		description = "Trojan:Win32/Etchfro.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 04 31 8a 16 32 c2 8a d0 c0 ea 04 c0 e0 04 } //01 00 
		$a_01_1 = {8a c1 c0 e8 04 c0 e1 04 0a c1 88 02 8a 4a 01 42 84 c9 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}