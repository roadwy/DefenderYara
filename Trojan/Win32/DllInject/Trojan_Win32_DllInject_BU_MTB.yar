
rule Trojan_Win32_DllInject_BU_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 03 00 "
		
	strings :
		$a_01_0 = {4c 6f 73 66 67 6b 73 6f 64 66 67 41 6f 73 6a 67 69 73 6a 64 67 6a } //03 00 
		$a_01_1 = {4a 69 6f 61 65 6a 67 66 69 39 61 65 73 6a 69 66 67 73 6a } //01 00 
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}