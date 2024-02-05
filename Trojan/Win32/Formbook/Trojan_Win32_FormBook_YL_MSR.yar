
rule Trojan_Win32_FormBook_YL_MSR{
	meta:
		description = "Trojan:Win32/FormBook.YL!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 43 6f 64 65 73 5c 56 65 72 73 69 6f 6e 33 5c 73 74 75 62 33 33 33 5c 52 65 6c 65 61 73 65 5c 73 74 75 62 33 33 33 2e 70 64 62 } //01 00 
		$a_01_1 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 4f 00 66 00 66 00 69 00 63 00 65 00 20 00 57 00 6f 00 72 00 64 00 } //01 00 
		$a_01_2 = {57 00 69 00 6e 00 57 00 6f 00 72 00 64 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}