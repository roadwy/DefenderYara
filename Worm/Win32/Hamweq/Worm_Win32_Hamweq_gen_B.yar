
rule Worm_Win32_Hamweq_gen_B{
	meta:
		description = "Worm:Win32/Hamweq.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 15 8b 06 8b 4c 24 ?? 03 c3 51 8a 14 29 30 10 45 ff d7 3b e8 7c eb 8b 06 03 c3 43 [0-02] f6 } //1
		$a_01_1 = {59 6a 1a 99 59 f7 f9 80 c2 61 88 14 3e 46 3b 74 24 18 76 } //1
		$a_01_2 = {80 f9 30 7c 0e 80 f9 39 7f 09 04 0d c0 e0 04 02 c1 eb 11 80 f9 41 7c 12 80 f9 46 7f 0d c0 e0 04 02 c1 2c 37 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}