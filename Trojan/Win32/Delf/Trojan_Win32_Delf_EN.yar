
rule Trojan_Win32_Delf_EN{
	meta:
		description = "Trojan:Win32/Delf.EN,SIGNATURE_TYPE_PEHSTR,1f 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 63 20 63 6f 6e 66 69 67 20 64 68 63 70 20 64 65 70 65 6e 64 3d 20 64 68 63 70 73 72 76 } //0a 00 
		$a_01_1 = {6e 65 74 20 73 74 61 72 74 20 64 68 63 70 } //0a 00 
		$a_01_2 = {3a 2f 2f 73 75 76 2e 69 70 6b 38 38 38 38 2e 63 6e 2f 63 6f 75 6e 74 2f 63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d } //01 00 
		$a_01_3 = {5c 64 68 63 70 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}