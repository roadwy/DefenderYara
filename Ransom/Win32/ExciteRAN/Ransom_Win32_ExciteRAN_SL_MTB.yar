
rule Ransom_Win32_ExciteRAN_SL_MTB{
	meta:
		description = "Ransom:Win32/ExciteRAN.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 20 6b 65 79 20 69 20 72 65 71 75 69 72 65 64 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 2c 20 77 68 69 63 68 20 79 6f 75 20 63 61 6e 20 70 75 72 63 68 61 73 65 } //1 A key i required for decryption, which you can purchase
		$a_81_1 = {68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 73 70 65 63 69 61 6c 20 65 6e 63 72 79 70 74 69 6f 6e 20 70 72 6f 67 72 61 6d 20 21 21 } //1 have been encrypted with a special encryption program !!
		$a_81_2 = {50 41 59 20 31 30 30 24 20 77 69 74 68 20 42 69 74 63 6f 69 6e 20 74 6f 20 74 68 69 73 20 77 61 6c 6c 65 74 3a } //1 PAY 100$ with Bitcoin to this wallet:
		$a_81_3 = {45 78 63 69 74 65 52 41 4e } //1 ExciteRAN
		$a_81_4 = {76 69 61 20 74 68 69 73 20 63 6f 6e 74 61 63 74 20 65 6d 61 69 6c 20 22 65 78 63 69 74 65 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d } //1 via this contact email "excite@protonmail.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}