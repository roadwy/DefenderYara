
rule Trojan_Win32_Urelas_GPA_MTB{
	meta:
		description = "Trojan:Win32/Urelas.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 00 69 00 61 00 73 00 52 00 65 00 74 00 69 00 6e 00 61 } //01 00 
		$a_01_1 = {4e 00 65 00 77 00 62 00 61 00 64 00 75 00 67 00 69 } //01 00 
		$a_01_2 = {44 00 75 00 65 00 6c 00 50 00 6f 00 6b 00 65 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}