
rule Ransom_Win64_Akira_B{
	meta:
		description = "Ransom:Win64/Akira.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 6b 69 72 61 5f 72 65 61 64 6d 65 2e 74 78 74 } //1 akira_readme.txt
		$a_01_1 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN PUBLIC KEY-----
		$a_01_2 = {4d 6f 72 65 6f 76 65 72 2c 20 77 65 20 68 61 76 65 20 74 61 6b 65 6e 20 61 20 67 72 65 61 74 20 61 6d 6f 75 6e 74 20 6f 66 20 79 6f 75 72 20 63 6f 72 70 6f 72 61 74 65 20 64 61 74 61 20 70 72 69 6f 72 20 74 6f 20 65 6e 63 72 79 70 74 69 6f 6e 2e } //1 Moreover, we have taken a great amount of your corporate data prior to encryption.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}