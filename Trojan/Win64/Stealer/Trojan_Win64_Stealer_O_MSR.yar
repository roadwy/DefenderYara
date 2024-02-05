
rule Trojan_Win64_Stealer_O_MSR{
	meta:
		description = "Trojan:Win64/Stealer.O!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //Google\Chrome\User Data\Default\Login Data  01 00 
		$a_80_1 = {4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //Microsoft\Edge\User Data\Default\Login Data  01 00 
		$a_80_2 = {42 72 6f 77 73 65 72 5c 55 73 65 72 20 44 61 74 61 5c 4c 6f 63 61 6c 20 53 74 61 74 65 } //Browser\User Data\Local State  01 00 
		$a_80_3 = {49 6d 42 65 74 74 65 72 2e 70 64 62 } //ImBetter.pdb  01 00 
		$a_80_4 = {70 61 73 73 77 6f 72 64 3a } //password:  01 00 
		$a_80_5 = {43 68 72 6f 6d 65 43 6f 6f 6b 69 65 73 } //ChromeCookies  01 00 
		$a_80_6 = {42 72 61 76 65 43 6f 6f 6b 69 65 73 } //BraveCookies  01 00 
		$a_80_7 = {54 69 74 61 6e 43 6f 6f 6b 69 65 73 } //TitanCookies  00 00 
	condition:
		any of ($a_*)
 
}