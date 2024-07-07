
rule Ransom_MSIL_PadCrypt_A{
	meta:
		description = "Ransom:MSIL/PadCrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 61 64 43 72 79 70 74 20 33 2e 30 2e 65 78 65 } //1 PadCrypt 3.0.exe
		$a_01_1 = {24 35 61 37 31 62 33 35 38 2d 66 30 32 35 2d 34 38 66 38 2d 39 66 61 65 2d 38 32 32 32 65 65 34 61 64 31 39 34 } //1 $5a71b358-f025-48f8-9fae-8222ee4ad194
		$a_01_2 = {5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 24 00 } //1 _Encrypted$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}