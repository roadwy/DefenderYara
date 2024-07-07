
rule Ransom_MSIL_Mallox_MA_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 9f a3 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 6e 00 00 00 f3 00 00 00 fb 04 00 00 34 0d 00 00 fb 05 00 00 04 } //1
		$a_01_1 = {34 32 38 66 37 33 66 66 2d 30 61 36 65 2d 34 32 32 31 2d 62 63 61 39 2d 37 64 62 36 35 62 63 63 33 34 62 33 } //1 428f73ff-0a6e-4221-bca9-7db65bcc34b3
		$a_01_2 = {5a 6a 77 69 6d 78 66 78 7a 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Zjwimxfxz.Properties
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}