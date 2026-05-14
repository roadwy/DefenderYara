
rule Ransom_Win64_Crimson_MRZ_MTB{
	meta:
		description = "Ransom:Win64/Crimson.MRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //3 YOUR FILES ARE ENCRYPTED
		$a_01_1 = {43 52 49 4d 53 4f 4e 20 52 41 4e 53 4f 4d 57 41 52 45 20 76 35 2e 30 } //3 CRIMSON RANSOMWARE v5.0
		$a_01_2 = {21 21 21 5f 43 52 49 4d 53 4f 4e 5f 52 45 41 44 4d 45 5f 21 21 21 2e 74 78 74 } //3 !!!_CRIMSON_README_!!!.txt
		$a_01_3 = {53 65 6e 64 20 25 64 20 42 54 43 20 74 6f } //1 Send %d BTC to
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1) >=10
 
}