
rule Ransom_MSIL_WannaMadCrypt_PB_MTB{
	meta:
		description = "Ransom:MSIL/WannaMadCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } //01 00  README.txt
		$a_01_1 = {59 00 6f 00 75 00 20 00 77 00 65 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 57 00 61 00 6e 00 6e 00 61 00 4d 00 61 00 64 00 } //01 00  You were encrypted by WannaMad
		$a_01_2 = {68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  has been encrypted
		$a_01_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 61 00 6e 00 6e 00 61 00 4d 00 61 00 64 00 } //00 00  C:\Program Files\System32\WannaMad
	condition:
		any of ($a_*)
 
}