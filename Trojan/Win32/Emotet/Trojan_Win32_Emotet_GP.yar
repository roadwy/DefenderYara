
rule Trojan_Win32_Emotet_GP{
	meta:
		description = "Trojan:Win32/Emotet.GP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 00 72 00 65 00 76 00 69 00 65 00 77 00 73 00 34 00 31 00 67 00 65 00 6f 00 72 00 67 00 65 00 4b 00 74 00 63 00 } //01 00 
		$a_01_1 = {5c 53 4f 46 54 57 41 52 45 5c 44 45 56 45 4c 5c 44 45 42 55 47 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}