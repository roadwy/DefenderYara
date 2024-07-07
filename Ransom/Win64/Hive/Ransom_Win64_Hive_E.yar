
rule Ransom_Win64_Hive_E{
	meta:
		description = "Ransom:Win64/Hive.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {21 65 72 72 6f 72 3a 20 6e 6f 20 66 6c 61 67 20 2d 75 20 3c 6c 6f 67 69 6e 3e 3a 3c 70 61 73 73 77 6f 72 90 01 01 3e 20 70 72 6f 76 69 64 65 64 90 00 } //1
		$a_02_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 65 78 90 01 01 61 6e 64 20 33 32 2d 62 79 74 65 20 6b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}