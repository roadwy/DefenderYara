
rule Trojan_Win32_Brackash_gen_A{
	meta:
		description = "Trojan:Win32/Brackash.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,11 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {74 0d 53 56 68 f4 05 00 00 50 e8 90 01 02 ff ff a1 90 00 } //07 00 
		$a_03_1 = {50 6a 0a e8 90 01 02 ff ff a3 90 01 04 c3 90 00 } //06 00 
		$a_00_2 = {53 68 65 6c 6c 45 76 65 6e 74 2e 64 6c 6c 00 48 6b 4f 66 66 00 48 6b 4f 6e 00 } //06 00 
		$a_01_3 = {72 61 6e 64 6f 6d 66 75 6e 63 69 6f 6e 64 69 72 6d 65 6d 6f 72 79 68 61 74 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}