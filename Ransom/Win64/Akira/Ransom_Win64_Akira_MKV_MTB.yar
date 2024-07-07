
rule Ransom_Win64_Akira_MKV_MTB{
	meta:
		description = "Ransom:Win64/Akira.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 14 24 48 8b 94 24 18 01 00 00 8b 3c 24 03 7c 24 34 33 42 04 44 33 6a 0c 44 33 7a 14 44 33 72 18 33 6a 1c 33 72 20 33 7a 24 33 5a 28 44 33 5a 2c 44 33 42 38 33 4a 3c 89 44 24 70 8b 44 24 4c 41 03 c4 44 89 6c 24 58 33 42 08 44 8b 6c 24 18 } //5
		$a_01_1 = {74 68 65 20 69 6e 74 65 72 6e 61 6c 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 20 6f 66 20 79 6f 75 72 20 63 6f 6d 70 61 6e 79 20 69 73 20 66 75 6c 6c 79 20 6f 72 20 70 61 72 74 69 61 6c 6c 79 20 64 65 61 64 2c 20 61 6c 6c 20 79 6f 75 72 20 62 61 63 6b 75 70 73 } //5 the internal infrastructure of your company is fully or partially dead, all your backups
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}