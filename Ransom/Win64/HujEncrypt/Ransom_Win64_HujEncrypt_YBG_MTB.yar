
rule Ransom_Win64_HujEncrypt_YBG_MTB{
	meta:
		description = "Ransom:Win64/HujEncrypt.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 02 c0 32 ca 41 32 c0 41 32 c3 88 4e 05 0f b6 56 09 41 32 c1 44 0f b6 4e 0a 88 46 06 0f b6 c3 } //4
		$a_01_1 = {68 75 6a 5f 65 6e 63 72 79 70 74 2e 6c 6f 67 } //1 huj_encrypt.log
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}