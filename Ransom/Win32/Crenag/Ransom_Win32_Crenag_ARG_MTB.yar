
rule Ransom_Win32_Crenag_ARG_MTB{
	meta:
		description = "Ransom:Win32/Crenag.ARG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {59 83 65 fc 00 8b 35 90 01 04 8b ce 83 e1 1f 33 35 90 01 04 d3 ce 89 75 e4 c7 45 fc 90 00 } //01 00 
		$a_00_1 = {43 00 72 00 79 00 70 00 74 00 6f 00 43 00 79 00 6d 00 75 00 6c 00 61 00 74 00 65 00 5f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 74 00 78 00 74 00 } //01 00  CryptoCymulate_Decrypted.txt
		$a_00_2 = {43 00 72 00 79 00 70 00 74 00 6f 00 43 00 79 00 6d 00 75 00 6c 00 61 00 74 00 65 00 5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 74 00 78 00 74 00 } //00 00  CryptoCymulate_Encrypted.txt
	condition:
		any of ($a_*)
 
}