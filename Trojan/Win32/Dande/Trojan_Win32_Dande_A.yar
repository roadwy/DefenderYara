
rule Trojan_Win32_Dande_A{
	meta:
		description = "Trojan:Win32/Dande.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 41 4e 44 45 5f 49 4e 53 54 5f 53 43 53 } //01 00 
		$a_01_1 = {ff d0 8b f0 8b 56 3c 8b 44 32 78 8b 4d 0c 8b d1 03 c6 c1 ea 10 89 45 f8 85 d2 75 } //00 00 
	condition:
		any of ($a_*)
 
}