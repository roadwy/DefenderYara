
rule Trojan_BAT_LummaC_NLI_MTB{
	meta:
		description = "Trojan:BAT/LummaC.NLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {25 47 11 33 16 ?? ?? 00 00 0a 61 d2 52 } //2
		$a_03_1 = {11 25 11 1b 61 13 0e ?? ?? ?? ?? ?? 16 13 2e } //1
		$a_01_2 = {61 63 30 34 39 62 66 61 2d 32 64 64 38 2d 34 66 31 61 2d 39 33 31 34 2d 31 31 65 33 66 65 64 36 31 34 35 34 } //1 ac049bfa-2dd8-4f1a-9314-11e3fed61454
		$a_01_3 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //1 kLjw4iIsCLsZtxc4lksN0j
		$a_01_4 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}