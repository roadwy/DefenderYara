
rule Trojan_Win32_Saiterec_A{
	meta:
		description = "Trojan:Win32/Saiterec.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {69 6e 63 72 61 74 65 73 2e 63 6f 6d 2f 6c 6f 67 2e 70 68 70 00 } //02 00 
		$a_01_1 = {69 4d 6f 64 75 6c 65 2e 64 6c 6c 00 66 00 69 00 6f 00 73 00 } //02 00 
		$a_01_2 = {26 61 66 66 69 64 3d 00 53 6f 66 74 77 61 72 65 } //01 00 
		$a_01_3 = {25 73 3f 73 69 64 3d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}