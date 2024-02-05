
rule Trojan_Win32_Multsarch_T{
	meta:
		description = "Trojan:Win32/Multsarch.T,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {73 74 69 6d 75 6c 70 72 6f 66 69 74 2e 63 6f 6d } //02 00 
		$a_01_1 = {2f 73 6d 73 2d 61 70 69 2f } //01 00 
		$a_01_2 = {2f 73 6d 73 5f 66 72 6f 6d 5f 73 6f 66 74 2e 70 68 70 3f 75 73 65 72 5f 70 68 6f 6e 65 3d } //01 00 
		$a_01_3 = {2f 73 6f 66 74 5f 74 69 6e 66 6f 2e 70 68 70 3f 63 6f 64 65 3d } //01 00 
		$a_01_4 = {2f 70 61 79 65 64 5f 71 75 65 72 69 65 73 2e 70 68 70 3f 71 75 65 72 79 3d } //01 00 
		$a_01_5 = {26 74 6f 72 72 65 6e 74 5f 69 64 3d } //01 00 
		$a_01_6 = {26 70 6c 61 74 6e 69 6b 5f 69 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}