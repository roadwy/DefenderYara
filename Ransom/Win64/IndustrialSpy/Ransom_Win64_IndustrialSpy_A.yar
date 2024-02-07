
rule Ransom_Win64_IndustrialSpy_A{
	meta:
		description = "Ransom:Win64/IndustrialSpy.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0d 0a 64 65 c7 90 01 03 6c 20 25 31 c7 90 01 03 0d 0a 69 66 c7 90 01 03 20 6e 6f 74 c7 90 01 03 20 65 72 72 c7 90 01 03 6f 72 6c 65 c7 90 01 03 76 65 6c 20 c7 90 01 03 30 20 67 6f c7 90 01 03 74 6f 20 72 c7 90 01 03 65 70 0d 0a c7 90 01 03 64 65 6c 20 90 00 } //01 00 
		$a_03_1 = {66 0d 0a 3a c7 90 01 03 72 65 70 0d c7 90 01 03 0a 64 65 6c c7 90 01 03 20 25 31 0d c7 90 01 03 0a 69 66 20 c7 90 01 03 6e 6f 74 20 c7 90 01 03 65 72 72 6f c7 90 01 03 72 6c 65 76 c7 90 01 03 65 6c 20 30 c7 90 01 03 20 67 6f 74 90 00 } //02 00 
		$a_01_2 = {74 65 6d 70 2e 63 6d 64 20 25 73 } //fd ff  temp.cmd %s
		$a_01_3 = {88 13 00 00 01 00 00 00 00 00 40 06 00 00 00 00 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f 1f } //00 00 
	condition:
		any of ($a_*)
 
}