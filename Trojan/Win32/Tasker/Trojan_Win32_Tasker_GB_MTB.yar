
rule Trojan_Win32_Tasker_GB_MTB{
	meta:
		description = "Trojan:Win32/Tasker.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {b7 d0 66 ff c8 81 fc c4 4d 28 21 66 87 d2 66 f7 d8 80 e6 31 66 81 da e9 3a 66 f7 d0 66 ff c2 3b c6 66 35 b8 1d 66 0f bd d3 66 05 12 3b 66 33 d8 } //02 00 
		$a_01_1 = {4e 91 90 3c a4 ba a0 5e 63 a2 3a cc 67 1a cd 85 86 c1 e0 7a 77 8e 33 28 c5 25 ce 78 d5 ba 3c eb } //01 00 
		$a_01_2 = {e0 00 02 01 0b 01 0e 22 00 b4 02 00 00 a4 08 00 00 00 00 00 78 94 49 } //00 00 
	condition:
		any of ($a_*)
 
}