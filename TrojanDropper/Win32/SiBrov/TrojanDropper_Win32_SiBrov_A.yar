
rule TrojanDropper_Win32_SiBrov_A{
	meta:
		description = "TrojanDropper:Win32/SiBrov.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {b8 cd cc cc cc 4e f7 a5 90 01 04 c1 ea 90 01 01 8a c2 8a ca c0 e0 90 01 01 02 c8 8b 85 90 01 04 02 c9 2a c1 04 90 01 01 88 06 8b c2 89 85 90 01 04 85 c0 90 00 } //01 00 
		$a_01_1 = {47 65 74 46 69 6c 65 53 69 7a 65 } //01 00 
		$a_01_2 = {52 65 61 64 46 69 6c 65 } //01 00 
		$a_01_3 = {43 72 65 61 74 65 46 69 6c 65 41 } //01 00 
		$a_01_4 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } //00 00 
		$a_00_5 = {5d 04 00 00 5c } //a6 04 
	condition:
		any of ($a_*)
 
}