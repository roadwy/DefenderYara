
rule Ransom_Win32_Sofilblock_A{
	meta:
		description = "Ransom:Win32/Sofilblock.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2a 2e 62 6c 6f 63 6b 90 02 15 2e 64 65 63 72 79 70 74 90 00 } //1
		$a_03_1 = {2a 2e 77 72 69 90 02 10 2a 2e 63 73 73 90 02 10 2a 2e 61 73 6d 90 02 10 2a 2e 68 74 6d 6c 90 00 } //1
		$a_03_2 = {46 69 6c 65 73 6f 70 2e 74 78 74 2e 62 6c 6f 63 6b 90 02 10 62 67 6a 70 67 90 00 } //1
		$a_01_3 = {8b 10 ff 12 f7 d8 83 d2 00 f7 da 52 50 b2 01 8b c6 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}