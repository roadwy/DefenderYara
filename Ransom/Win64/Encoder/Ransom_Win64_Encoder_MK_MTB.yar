
rule Ransom_Win64_Encoder_MK_MTB{
	meta:
		description = "Ransom:Win64/Encoder.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 72 65 6d 61 69 6e 20 65 6e 63 72 79 70 74 65 64 2e } //10 Your files remain encrypted.
		$a_01_1 = {41 6c 6c 20 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 } //5 All  of your files have been encrypted with
		$a_01_2 = {45 6e 74 65 72 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 20 66 72 6f 6d 20 79 6f 75 72 20 2e } //3 Enter the decryption key from your .
		$a_01_3 = {2d 6e 6f 73 70 72 65 61 64 2d 2d 6e 6f 73 70 72 65 61 64 55 53 45 52 50 52 4f 46 49 4c 45 44 65 73 6b 74 6f 70 } //2 -nospread--nospreadUSERPROFILEDesktop
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=20
 
}