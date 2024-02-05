
rule Trojan_Win32_SVCLoader_AM_MTB{
	meta:
		description = "Trojan:Win32/SVCLoader.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6c 6c 69 70 73 65 } //01 00 
		$a_01_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //01 00 
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_4 = {46 69 6c 6c 52 65 63 74 } //01 00 
		$a_01_5 = {73 78 76 2e 64 6c 6c } //01 00 
		$a_01_6 = {4c 6f 61 64 4c 69 62 72 61 72 79 43 } //00 00 
	condition:
		any of ($a_*)
 
}