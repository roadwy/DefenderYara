
rule Trojan_Win32_Kitchener_A_dha{
	meta:
		description = "Trojan:Win32/Kitchener.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 49 00 4d 00 45 00 5c 00 6d 00 63 00 6f 00 64 00 73 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_01_1 = {4d 79 20 53 61 6d 70 6c 65 20 53 65 72 76 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}