
rule Trojan_Win32_Zenpack_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {79 69 65 6c 64 69 6e 67 2c 35 74 77 6f 6d 61 6b 65 53 35 } //05 00 
		$a_01_1 = {73 65 74 75 73 73 68 65 2e 64 4d 61 6c 65 61 70 70 65 61 72 68 } //05 00 
		$a_01_2 = {67 61 74 68 65 72 65 64 6c 65 73 73 65 72 64 61 79 74 68 65 72 65 2e 6b 73 65 65 64 69 74 73 68 65 2e 64 } //05 00 
		$a_01_3 = {76 6f 6d 6d 64 65 2e 70 64 62 } //05 00 
		$a_01_4 = {57 64 69 76 69 64 65 64 50 66 6f 72 6d 42 } //00 00 
	condition:
		any of ($a_*)
 
}