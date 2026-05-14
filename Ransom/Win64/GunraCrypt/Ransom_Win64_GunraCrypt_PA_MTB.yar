
rule Ransom_Win64_GunraCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/GunraCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 33 41 44 4d 33 2e 74 78 74 } //3 R3ADM3.txt
		$a_01_1 = {25 73 2f 25 73 2e 6b 65 79 73 74 6f 72 65 } //1 %s/%s.keystore
		$a_01_2 = {59 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your data has been encrypted
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}