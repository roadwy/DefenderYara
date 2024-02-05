
rule Trojan_Win32_DllInject_BY_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 4a 69 6a 61 73 67 6f 69 73 64 6a 67 73 64 69 6a } //02 00 
		$a_01_1 = {44 6f 69 61 73 64 6f 66 69 61 73 64 69 66 6f 61 64 73 6a } //02 00 
		$a_01_2 = {43 6a 76 62 6f 69 73 64 6a 59 73 6f 69 67 6a 69 73 6f 65 67 6a 69 73 65 } //02 00 
		$a_01_3 = {43 6f 69 73 67 6f 69 77 65 67 6f 69 65 68 67 65 64 69 66 6a 64 } //05 00 
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}