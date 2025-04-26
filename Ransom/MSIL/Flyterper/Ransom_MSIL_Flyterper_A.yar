
rule Ransom_MSIL_Flyterper_A{
	meta:
		description = "Ransom:MSIL/Flyterper.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 6e 76 6f 69 63 65 5c 48 69 44 64 45 6e 2d 54 65 41 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 69 6e 76 6f 69 63 65 2e 70 64 62 } //10 Invoice\HiDdEn-TeAr\obj\Debug\invoice.pdb
		$a_01_1 = {53 65 74 57 61 6c 6c 70 61 70 65 72 46 72 6f 6d 57 65 62 } //10 SetWallpaperFromWeb
		$a_00_2 = {41 45 53 5f 45 6e 63 72 79 70 74 } //10 AES_Encrypt
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10) >=20
 
}