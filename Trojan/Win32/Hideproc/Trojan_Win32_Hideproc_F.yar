
rule Trojan_Win32_Hideproc_F{
	meta:
		description = "Trojan:Win32/Hideproc.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 89 c7 88 cd 89 c8 c1 e0 10 66 89 c8 89 d1 c1 f9 02 78 09 f3 ab } //01 00 
		$a_11_1 = {74 48 69 64 65 46 69 6c 65 4d 61 70 70 69 6e 67 01 } //00 22 
		$a_6e_2 = {68 } //69 64  h
		$a_2e_3 = {6c 6c 00 48 69 64 65 50 72 6f 63 65 73 73 00 49 6e 73 74 61 6c 6c 48 6f 6f 6b 00 00 5d 04 00 00 9f 64 02 80 5c 24 00 00 a0 64 02 80 00 00 01 00 03 00 0e 00 a0 21 50 68 61 72 6d 6f 6f 6b 65 72 2e 41 00 00 01 40 05 82 34 00 04 00 80 10 00 00 96 e5 cc 34 db e4 b7 25 69 91 c1 55 40 02 00 80 5d 04 00 00 a0 } //64 02 
	condition:
		any of ($a_*)
 
}