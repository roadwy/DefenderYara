
rule Trojan_Win32_BHO_CK{
	meta:
		description = "Trojan:Win32/BHO.CK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {f2 ae f7 d1 2b f9 68 90 01 04 8b c1 8b f7 8b fa 68 04 01 00 00 c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d 7c 90 01 02 83 c9 ff f2 ae f7 d1 49 51 8d 4c 90 01 02 51 e8 90 00 } //01 00 
		$a_01_1 = {62 68 6f 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00 
		$a_00_2 = {43 4c 53 49 44 5c 25 73 5c 49 6e 70 72 6f 63 53 65 72 76 65 72 33 32 } //01 00 
		$a_01_3 = {6b 65 79 00 63 68 61 6e 6e 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}