
rule Trojan_AndroidOS_Coper_B{
	meta:
		description = "Trojan:AndroidOS/Coper.B,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {2f 64 6f 77 6e 6c 6f 61 64 69 6e 6a 65 63 74 3f 61 63 63 65 73 73 3d } //02 00 
		$a_01_1 = {73 74 61 72 74 48 69 64 64 65 6e 50 75 73 68 } //02 00 
		$a_01_2 = {73 70 65 63 69 66 69 63 42 61 74 74 65 72 79 4f 70 74 } //02 00 
		$a_01_3 = {26 74 79 70 65 3d 68 74 6d 6c 26 62 6f 74 69 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}