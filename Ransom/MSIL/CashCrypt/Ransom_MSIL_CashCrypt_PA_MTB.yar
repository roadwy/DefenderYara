
rule Ransom_MSIL_CashCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/CashCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 61 73 68 52 61 6e 73 6f 6d 77 61 72 65 2e 4b 65 79 41 75 74 68 } //01 00  CashRansomware.KeyAuth
		$a_01_1 = {67 65 74 5f 4d 6f 6e 65 72 6f 5f 4c 6f 67 6f 5f 73 76 67 } //01 00  get_Monero_Logo_svg
		$a_01_2 = {41 45 53 5f 45 6e 63 72 79 70 74 } //01 00  AES_Encrypt
		$a_01_3 = {67 65 74 5f 6d 6f 6e 65 72 6f 5f 69 63 6f 6e 5f 35 31 32 78 35 31 32 5f 6b 71 67 39 6e 35 6d 70 } //01 00  get_monero_icon_512x512_kqg9n5mp
		$a_01_4 = {43 61 73 68 52 61 6e 73 6f 6d 77 61 72 65 2e 55 6e 6b 6e 6f 77 6e 46 31 2e 72 65 73 6f 75 72 63 65 73 } //00 00  CashRansomware.UnknownF1.resources
	condition:
		any of ($a_*)
 
}