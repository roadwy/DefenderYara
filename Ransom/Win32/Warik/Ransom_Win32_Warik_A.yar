
rule Ransom_Win32_Warik_A{
	meta:
		description = "Ransom:Win32/Warik.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {31 f6 8d 74 26 00 8b 04 b5 ?? ?? ?? ?? 8d [0-10] e8 ?? ?? ff ff 85 c0 75 ?? 83 c6 01 81 fe ?? 00 00 00 75 } //3
		$a_03_1 = {83 c6 01 83 fe 79 0f [0-05] 8b 04 b5 ?? ?? ?? ?? 89 [0-04] 89 [0-04] e8 ?? ?? ?? ?? 85 c0 74 } //3
		$a_80_2 = {57 68 61 74 20 69 66 20 73 6f 6d 65 6f 6e 65 20 67 61 76 65 20 61 20 77 61 72 20 61 6e 64 20 4e 6f 62 6f 64 79 20 63 61 6d 65 3f } //What if someone gave a war and Nobody came?  1
		$a_80_3 = {62 6c 6f 63 6b 40 6d 61 69 6c 32 74 6f 72 2e 63 6f 6d } //block@mail2tor.com  1
		$a_80_4 = {4e 69 63 68 74 20 4b 6c 75 63 68 65 6e 21 20 4b 61 70 69 74 75 6c 69 65 72 65 6e 21 21 } //Nicht Kluchen! Kapitulieren!!  1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}