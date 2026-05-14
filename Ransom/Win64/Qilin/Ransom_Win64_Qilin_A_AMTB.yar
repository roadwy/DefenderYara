
rule Ransom_Win64_Qilin_A_AMTB{
	meta:
		description = "Ransom:Win64/Qilin.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 70 65 6e 65 74 72 61 74 65 64 20 62 79 20 51 69 6c 69 6e } //Your network has been penetrated by Qilin  1
		$a_80_1 = {47 6c 6f 62 61 6c 5c 51 49 4c 49 4e 5f 45 4e 43 52 59 50 54 } //Global\QILIN_ENCRYPT  1
		$a_80_2 = {52 45 41 44 4d 45 5f 51 49 4c 49 4e } //README_QILIN  1
		$a_80_3 = {41 6c 6c 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 51 69 6c 69 6e 20 72 61 6e 73 6f 6d 77 61 72 65 } //All files have been encrypted by Qilin ransomware  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}