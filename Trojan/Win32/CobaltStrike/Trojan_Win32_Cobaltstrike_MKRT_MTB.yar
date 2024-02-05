
rule Trojan_Win32_Cobaltstrike_MKRT_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MKRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 c8 c1 e8 12 24 07 0c f0 88 02 89 c8 c1 e8 0c 24 3f 0c 80 88 42 01 89 c8 c1 e8 06 24 3f 0c 80 88 42 02 80 e1 3f 80 c9 80 88 4a 03 b9 04 00 00 00 48 81 c4 98 } //01 00 
		$a_00_1 = {4c 6f 63 61 6c 5c 52 75 73 74 42 61 63 6b 74 72 61 63 65 4d 75 74 65 78 } //01 00 
		$a_81_2 = {72 75 73 74 5f 65 68 5f 70 65 72 73 6f 6e 61 6c 69 74 79 } //00 00 
	condition:
		any of ($a_*)
 
}