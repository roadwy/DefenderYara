
rule Trojan_Win32_CryptInject_SF_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.SF!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 35 5c 50 72 6f 6a 65 63 74 73 5c 42 61 73 65 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 42 61 73 65 4c 6f 61 64 65 72 2e 70 64 62 } //01 00 
		$a_01_1 = {48 61 63 6b 20 61 63 74 69 76 61 74 65 64 } //01 00 
		$a_01_2 = {68 74 74 70 3a 2f 2f 74 66 32 68 61 63 6b 2e 63 6f 6d 2f 64 61 73 68 62 6f 61 72 64 } //01 00 
		$a_01_3 = {5c 2e 5c 70 69 70 65 5c } //00 00 
	condition:
		any of ($a_*)
 
}