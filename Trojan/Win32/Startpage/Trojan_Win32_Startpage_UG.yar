
rule Trojan_Win32_Startpage_UG{
	meta:
		description = "Trojan:Win32/Startpage.UG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 33 36 30 73 65 55 52 4c } //01 00 
		$a_01_1 = {5c 64 61 6f 2e 69 63 6f } //01 00 
		$a_01_2 = {53 74 61 72 74 20 50 61 67 65 } //01 00 
		$a_01_3 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b } //01 00 
		$a_01_4 = {61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 } //00 00 
	condition:
		any of ($a_*)
 
}