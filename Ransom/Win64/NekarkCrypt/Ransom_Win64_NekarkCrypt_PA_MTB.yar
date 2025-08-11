
rule Ransom_Win64_NekarkCrypt_PA_MTB{
	meta:
		description = "Ransom:Win64/NekarkCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 52 45 41 44 4d 45 2e 74 78 74 } //1 \README.txt
		$a_01_1 = {2e 70 79 74 68 6f 6e 61 6e 79 77 68 65 72 65 2e 63 6f 6d } //1 .pythonanywhere.com
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //4 Your files have been encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*4) >=6
 
}
rule Ransom_Win64_NekarkCrypt_PA_MTB_2{
	meta:
		description = "Ransom:Win64/NekarkCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 20 42 54 43 } //1 Pay BTC
		$a_01_1 = {2e 63 72 6f 77 64 73 74 72 69 6b 65 } //1 .crowdstrike
		$a_01_2 = {5c 48 69 43 72 6f 77 64 53 74 72 69 6b 65 2e 74 78 74 } //2 \HiCrowdStrike.txt
		$a_01_3 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 65 6e 63 72 79 70 74 65 64 3a } //1 Successfully encrypted:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}