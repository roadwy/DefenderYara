
rule Trojan_Win32_Xpack_C_MTB{
	meta:
		description = "Trojan:Win32/Xpack.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 72 72 68 64 74 50 69 75 } //02 00  ErrhdtPiu
		$a_01_1 = {53 64 66 67 4c 6a 68 67 66 } //02 00  SdfgLjhgf
		$a_01_2 = {57 65 72 67 56 67 68 6a } //01 00  WergVghj
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}