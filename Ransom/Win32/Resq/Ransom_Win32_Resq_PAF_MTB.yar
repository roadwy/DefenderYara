
rule Ransom_Win32_Resq_PAF_MTB{
	meta:
		description = "Ransom:Win32/Resq.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b fa 8b ca c1 c7 0f c1 c1 0d 33 f9 c1 ea 0a 33 fa 8b ce 8b d6 c1 c9 07 c1 c2 0e 33 d1 c1 ee 03 33 d6 03 fa } //0a 00 
		$a_03_1 = {0b c8 8b 85 90 01 04 03 c6 03 ca 03 ce 89 85 90 01 04 8b f0 89 8d 90 01 04 c1 c0 07 8b d1 c1 ce 0b 33 f0 c1 ca 0d 8b 85 90 01 04 c1 c8 06 90 00 } //01 00 
		$a_01_2 = {4e 45 54 57 4f 52 4b 20 48 41 53 20 42 45 45 4e 20 50 45 4e 45 54 52 41 54 45 44 } //01 00 
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 } //01 00 
		$a_00_4 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}