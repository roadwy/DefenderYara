
rule Trojan_Win32_Nokec_A{
	meta:
		description = "Trojan:Win32/Nokec.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6c 75 67 69 6e 2f 73 63 72 69 70 74 5f 6e 2e 70 68 70 3f 63 6f 64 65 3d } //01 00 
		$a_01_1 = {67 6f 2f 63 6f 75 6e 74 2e 70 68 70 3f 67 6f 3d } //01 00 
		$a_01_2 = {69 66 20 65 78 69 73 74 20 22 00 } //01 00 
		$a_01_3 = {6b 6f 64 65 63 00 } //01 00 
		$a_01_4 = {4d 6f 7a 69 6c 6c 61 57 69 6e 64 6f 77 43 6c 61 73 73 00 00 ff ff } //00 00 
	condition:
		any of ($a_*)
 
}