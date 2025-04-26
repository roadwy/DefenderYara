
rule Ransom_Win32_Conti_RQ_MTB{
	meta:
		description = "Ransom:Win32/Conti.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 63 75 72 72 65 6e 74 6c 79 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 43 4f 4e 54 49 20 73 74 72 61 69 6e } //1 All of your files are currently encrypted by CONTI strain
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 63 6f 6e 74 69 72 65 63 6f 76 65 72 79 2e 62 65 73 74 } //1 https://contirecovery.best
		$a_01_2 = {68 74 74 70 3a 2f 2f 63 6f 6e 74 69 72 65 63 6a 34 68 62 7a 6d 79 7a 75 79 64 79 7a 72 76 6d 32 63 36 35 62 6c 6d 76 68 6f 6a 32 63 76 66 32 35 7a 71 6a 32 64 77 72 72 71 63 71 35 6f 61 64 2e 6f 6e 69 6f 6e } //1 http://contirecj4hbzmyzuydyzrvm2c65blmvhoj2cvf25zqj2dwrrqcq5oad.onion
		$a_01_3 = {59 4f 55 20 53 48 4f 55 4c 44 20 42 45 20 41 57 41 52 45 21 } //1 YOU SHOULD BE AWARE!
		$a_01_4 = {4a 75 73 74 20 69 6e 20 63 61 73 65 2c 20 69 66 20 79 6f 75 20 74 72 79 20 74 6f 20 69 67 6e 6f 72 65 20 75 73 2e 20 57 65 27 76 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 79 6f 75 72 20 64 61 74 61 20 61 6e 64 20 61 72 65 20 72 65 61 64 79 20 74 6f 20 70 75 62 6c 69 73 68 20 69 74 20 6f 6e 20 6f 75 74 20 6e 65 77 73 20 77 65 62 73 69 74 65 20 69 66 20 79 6f 75 20 64 6f 20 6e 6f 74 20 72 65 73 70 6f 6e 64 2e 20 53 6f 20 69 74 20 77 69 6c 6c 20 62 65 20 62 65 74 74 65 72 20 66 6f 72 20 62 6f 74 68 20 73 69 64 65 73 20 69 66 20 79 6f 75 20 63 6f 6e 74 61 63 74 20 75 73 20 41 53 41 50 } //1 Just in case, if you try to ignore us. We've downloaded your data and are ready to publish it on out news website if you do not respond. So it will be better for both sides if you contact us ASAP
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}