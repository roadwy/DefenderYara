
rule Ransom_MSIL_FileCryptor_AYB_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {07 09 9a 28 26 00 00 0a 13 04 06 11 04 6f 27 00 00 0a 28 01 00 00 2b 2c 0d 07 09 9a 7e 01 00 00 04 28 02 00 00 06 09 17 58 0d 09 07 8e 69 32 d0 } //7
		$a_01_1 = {24 37 34 38 37 31 37 34 38 2d 64 30 61 31 2d 34 66 61 66 2d 39 65 30 61 2d 39 31 32 61 34 61 33 32 62 64 61 36 } //3 $74871748-d0a1-4faf-9e0a-912a4a32bda6
		$a_01_2 = {45 6e 63 72 79 70 74 46 6f 6c 64 65 72 } //1 EncryptFolder
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=11
 
}