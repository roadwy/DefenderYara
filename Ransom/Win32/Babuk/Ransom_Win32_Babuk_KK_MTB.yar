
rule Ransom_Win32_Babuk_KK_MTB{
	meta:
		description = "Ransom:Win32/Babuk.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a b9 ff 0f 40 00 [0-10] 88 b9 ff 0f 40 00 } //10
		$a_01_1 = {8a 9a 00 10 40 00 80 c3 1c c0 cb 2f c0 c3 1c c0 cb 24 88 9a 00 10 40 00 42 81 fa 9b 31 02 00 75 } //10
		$a_01_2 = {6d 20 73 6f 20 63 6f 6f 6c 20 3a 29 } //5 m so cool :)
		$a_01_3 = {59 65 61 70 20 2c 20 69 60 6d 20 61 20 62 61 64 20 6d 6f 74 68 65 72 20 66 75 63 6b 65 72 20 21 } //3 Yeap , i`m a bad mother fucker !
		$a_01_4 = {48 6f 77 20 6c 61 6d 65 20 63 61 6e 20 75 20 62 65 20 3f } //2 How lame can u be ?
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=20
 
}