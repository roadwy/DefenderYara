
rule Trojan_Win32_Encriyoko_A{
	meta:
		description = "Trojan:Win32/Encriyoko.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 53 45 4e 4b 41 4b 55 5f 49 53 43 48 49 4e 41 5d 5d 5d 00 } //01 00 
		$a_01_1 = {6b 72 65 63 79 63 6c 65 00 00 00 00 72 61 76 62 69 6e } //01 00 
		$a_01_2 = {5c 76 78 73 75 72 2e 62 69 6e 00 } //01 00 
		$a_01_3 = {6e 65 70 69 61 2e 64 75 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}