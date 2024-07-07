
rule Ransom_Win32_Genasom_BQ{
	meta:
		description = "Ransom:Win32/Genasom.BQ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 4f 57 20 54 4f 20 44 45 43 52 59 50 54 20 46 49 4c 45 53 2e } //2 HOW TO DECRYPT FILES.
		$a_01_1 = {4e 6f 62 6f 64 79 20 63 61 6e 20 68 65 6c 70 20 79 6f 75 20 2d 20 65 76 65 6e 20 64 6f 6e 27 74 20 74 72 79 } //4 Nobody can help you - even don't try
		$a_01_2 = {57 65 20 63 61 6e 20 68 65 6c 70 20 74 6f 20 73 6f 6c 76 65 20 74 68 69 73 20 74 61 73 6b 20 66 6f 72 20 31 32 30 24 20 76 69 61 20 77 69 72 65 20 74 72 61 6e 73 66 65 72 } //3 We can help to solve this task for 120$ via wire transfer
		$a_03_3 = {8b 75 08 8b fe 33 d2 8b 4d 0c 83 fa 10 75 02 33 d2 ac 32 82 90 01 02 40 00 aa 42 49 75 ed 90 00 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*4+(#a_01_2  & 1)*3+(#a_03_3  & 1)*3) >=9
 
}