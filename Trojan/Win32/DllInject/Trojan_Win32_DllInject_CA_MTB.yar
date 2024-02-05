
rule Trojan_Win32_DllInject_CA_MTB{
	meta:
		description = "Trojan:Win32/DllInject.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 69 6f 73 75 6f 6f 65 67 66 68 64 68 66 75 64 75 } //02 00 
		$a_01_1 = {4f 69 73 69 64 61 73 68 67 73 75 65 67 68 64 68 } //02 00 
		$a_01_2 = {43 69 6f 61 6f 69 66 61 6a 61 73 69 66 6a } //02 00 
		$a_01_3 = {4b 6f 69 61 73 64 67 6a 69 6f 73 64 67 69 6f 73 64 6a } //05 00 
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}