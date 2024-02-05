
rule Trojan_Win32_Urelas_O{
	meta:
		description = "Trojan:Win32/Urelas.O,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 38 4d 53 4d 50 75 e8 68 00 02 00 00 50 8d 85 90 01 04 50 e8 90 00 } //01 00 
		$a_01_1 = {67 00 6f 00 6c 00 66 00 69 00 6e 00 66 00 6f 00 2e 00 69 00 6e 00 69 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}