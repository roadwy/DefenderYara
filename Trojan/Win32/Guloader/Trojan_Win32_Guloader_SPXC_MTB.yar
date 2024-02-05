
rule Trojan_Win32_Guloader_SPXC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 6c 6f 6d 72 61 61 64 65 2e 41 66 66 } //01 00 
		$a_01_1 = {44 69 73 64 69 70 6c 6f 6d 61 74 69 7a 65 2e 6f 76 65 } //01 00 
		$a_01_2 = {50 61 6d 70 61 73 2e 73 6e 69 } //01 00 
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 65 6c 6f 64 79 69 6e 67 5c 6d 65 61 6e 64 72 6f 75 73 } //00 00 
	condition:
		any of ($a_*)
 
}