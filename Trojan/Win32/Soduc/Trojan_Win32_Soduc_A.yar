
rule Trojan_Win32_Soduc_A{
	meta:
		description = "Trojan:Win32/Soduc.A,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 63 64 6f 73 2e 6c 6e 6b 00 } //01 00 
		$a_01_1 = {63 6d 75 63 6f 64 65 2e 63 6d 63 6f 64 00 } //01 00 
		$a_01_2 = {75 63 64 6f 73 2e 70 70 64 73 00 } //01 00 
		$a_01_3 = {6f 72 74 68 73 65 74 00 } //0a 00  牯桴敳t
		$a_01_4 = {68 74 74 70 3a 2f 2f 31 32 32 2e 32 32 34 2e 39 2e 31 32 30 3a 38 30 32 32 2f 49 6e 73 65 72 74 62 7a 2e 61 73 70 78 3f 6d 63 69 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}