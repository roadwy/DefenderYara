
rule Trojan_Win32_Neoreblamy_KZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.KZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {4f 4d 47 3e 2e 3c 20 49 20 64 6f 6e 27 74 20 6b 6e 6f 77 21 } //01 00 
		$a_81_1 = {6d 6c 2e 20 66 72 6f 6d 20 63 75 70 20 23 } //01 00 
		$a_81_2 = {66 78 6f 74 79 62 79 6a 6b 63 67 64 74 72 74 6d 6f 6f 74 6d 66 63 77 6b 6f 67 74 69 76 65 6d 6b 76 6f 69 75 6c 67 6b 6a 6b 73 77 65 63 64 64 68 69 72 65 6b 64 } //01 00 
		$a_81_3 = {74 72 68 77 68 73 6c 6c 6c 6a 62 64 72 6d 6b 65 6b 76 6d 71 62 63 6d 75 74 71 68 78 67 77 77 66 72 73 61 75 63 62 6e 74 63 74 6d 71 68 6c 72 79 62 6e 72 68 } //00 00 
	condition:
		any of ($a_*)
 
}