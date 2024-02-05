
rule Trojan_Win32_Crastic_gen_A{
	meta:
		description = "Trojan:Win32/Crastic.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 53 50 8b 43 34 57 6a 04 68 00 20 00 00 52 50 ff 15 } //01 00 
		$a_01_1 = {63 73 72 73 73 2e 64 6c 6c 00 52 75 6e 64 6c 6c 33 32 57 00 53 65 72 76 69 63 65 4d 61 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}