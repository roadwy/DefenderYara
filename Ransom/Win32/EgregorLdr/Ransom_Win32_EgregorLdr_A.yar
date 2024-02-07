
rule Ransom_Win32_EgregorLdr_A{
	meta:
		description = "Ransom:Win32/EgregorLdr.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {05 4d d3 34 4d 01 43 90 01 01 8b c3 39 50 90 01 01 8b d3 8b 5d f8 1b c0 f7 d8 90 00 } //02 00 
		$a_03_1 = {05 34 4d d3 34 01 42 90 01 01 39 7a 90 01 01 8b fa 1b c0 f7 d8 90 00 } //02 00 
		$a_03_2 = {83 f8 01 0f 8e 90 01 04 8b c7 25 ff 0f 00 00 6a 90 01 01 5e 3d f0 0f 90 00 } //01 00 
		$a_00_3 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //01 00  expand 32-byte k
		$a_00_4 = {65 78 70 61 6e 64 20 31 36 20 62 79 74 65 20 6b } //00 00  expand 16 byte k
	condition:
		any of ($a_*)
 
}