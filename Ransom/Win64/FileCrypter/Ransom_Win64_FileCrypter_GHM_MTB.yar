
rule Ransom_Win64_FileCrypter_GHM_MTB{
	meta:
		description = "Ransom:Win64/FileCrypter.GHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 70 69 2e 76 61 6c 65 6e 74 69 6e 65 73 66 6f 72 65 76 65 72 2e 74 68 6d } //1 api.valentinesforever.thm
		$a_01_1 = {31 4c 30 76 33 59 30 75 46 30 72 33 76 33 72 34 6e 64 45 76 33 72 32 30 32 34 78 6f 78 6f } //1 1L0v3Y0uF0r3v3r4ndEv3r2024xoxo
		$a_01_2 = {59 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 65 78 66 69 6c 74 72 61 74 65 64 } //1 Your data has been exfiltrated
		$a_01_3 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 } //1 YOUR FILES HAVE BEEN ENCRYPTED
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}