
rule Ransom_Win32_Milicry_B{
	meta:
		description = "Ransom:Win32/Milicry.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 25 73 2e 73 61 67 65 00 } //01 00 
		$a_01_1 = {26 77 69 66 69 3d 6d 61 63 3a 25 73 7c 73 73 69 64 3a 25 73 7c 73 73 3a 25 64 00 00 2f 6d 61 70 73 2f 61 70 69 2f 62 72 6f 77 73 65 72 6c 6f 63 61 74 69 6f 6e 2f 6a 73 6f 6e 3f 62 72 6f 77 73 } //01 00 
		$a_01_2 = {21 52 65 63 6f 76 65 72 79 5f 25 73 2e 68 74 6d 6c } //01 00  !Recovery_%s.html
		$a_01_3 = {69 6d 61 67 65 73 20 61 6e 64 20 76 69 64 65 6f 73 20 61 6e 64 20 73 6f 20 6f 6e 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 73 6f 66 74 77 61 72 65 20 6b 6e 6f 77 6e 20 61 73 20 53 41 47 45 } //01 00  images and videos and so on were encrypted by software known as SAGE
		$a_01_4 = {00 64 61 74 00 6d 78 30 00 63 64 00 70 64 62 00 78 71 78 00 6f 6c 64 00 63 6e 74 00 72 74 70 00 } //00 00  搀瑡洀へ挀d摰b煸x汯d湣t瑲p
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}