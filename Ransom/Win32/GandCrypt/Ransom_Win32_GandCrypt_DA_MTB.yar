
rule Ransom_Win32_GandCrypt_DA_MTB{
	meta:
		description = "Ransom:Win32/GandCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {47 44 43 42 2d 44 45 43 52 59 50 54 2e 74 78 74 } //1 GDCB-DECRYPT.txt
		$a_81_1 = {72 61 6e 73 6f 6d 5f 69 64 } //1 ransom_id
		$a_81_2 = {47 61 6e 64 43 72 61 62 } //1 GandCrab
		$a_81_3 = {43 72 79 70 74 47 65 6e 4b 65 79 } //1 CryptGenKey
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}