
rule Trojan_Win32_Cleaman_A{
	meta:
		description = "Trojan:Win32/Cleaman.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c6 03 e9 6a 04 43 53 ff d6 85 c0 75 90 01 01 2b 90 01 03 83 ef 05 89 3b 90 00 } //01 00 
		$a_00_1 = {b9 00 50 00 00 66 39 4e 02 75 64 66 83 3e 02 75 5e } //00 00 
	condition:
		any of ($a_*)
 
}