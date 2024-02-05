
rule Trojan_Win32_Bandra_CB_MTB{
	meta:
		description = "Trojan:Win32/Bandra.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6f 63 2e 65 78 63 68 61 6e 67 65 2f 40 74 69 61 67 6f 61 32 36 } //01 00 
		$a_01_1 = {42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 73 } //01 00 
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 73 5c 25 73 5f 25 73 2e 74 78 74 } //01 00 
		$a_01_3 = {43 43 5c 25 73 5f 25 73 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}