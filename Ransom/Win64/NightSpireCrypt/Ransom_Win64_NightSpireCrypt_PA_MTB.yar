
rule Ransom_Win64_NightSpireCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/NightSpireCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_01_1 = {72 65 61 64 6d 65 2e 74 78 74 } //1 readme.txt
		$a_01_2 = {6e 69 67 68 74 73 70 69 72 65 74 65 61 6d } //1 nightspireteam
		$a_01_3 = {59 6f 75 72 20 73 65 72 76 65 72 73 20 61 6e 64 20 66 69 6c 65 73 20 61 72 65 20 6c 6f 63 6b 65 64 20 61 6e 64 20 63 6f 70 69 65 64 2e } //2 Your servers and files are locked and copied.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=5
 
}